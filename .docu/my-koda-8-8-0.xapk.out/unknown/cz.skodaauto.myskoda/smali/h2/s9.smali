.class public final Lh2/s9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg1/i1;


# instance fields
.field public final a:I

.field public b:Lay0/a;

.field public final c:Lgy0/f;

.field public final d:Ll2/f1;

.field public e:Lay0/k;

.field public final f:Z

.field public final g:[F

.field public final h:Ll2/g1;

.field public final i:Ll2/g1;

.field public j:Z

.field public final k:Ll2/g1;

.field public final l:Ll2/g1;

.field public final m:Lg1/w1;

.field public final n:Ll2/j1;

.field public final o:Ld2/g;

.field public final p:Ll2/f1;

.field public final q:Ll2/f1;

.field public final r:Lg1/a0;

.field public final s:Le1/b1;


# direct methods
.method public constructor <init>(FILay0/a;Lgy0/f;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p2, p0, Lh2/s9;->a:I

    .line 5
    .line 6
    iput-object p3, p0, Lh2/s9;->b:Lay0/a;

    .line 7
    .line 8
    iput-object p4, p0, Lh2/s9;->c:Lgy0/f;

    .line 9
    .line 10
    new-instance p3, Ll2/f1;

    .line 11
    .line 12
    invoke-direct {p3, p1}, Ll2/f1;-><init>(F)V

    .line 13
    .line 14
    .line 15
    iput-object p3, p0, Lh2/s9;->d:Ll2/f1;

    .line 16
    .line 17
    const/4 p3, 0x1

    .line 18
    iput-boolean p3, p0, Lh2/s9;->f:Z

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    if-nez p2, :cond_0

    .line 22
    .line 23
    new-array p2, v0, [F

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_0
    add-int/lit8 v1, p2, 0x2

    .line 27
    .line 28
    new-array v2, v1, [F

    .line 29
    .line 30
    move v3, v0

    .line 31
    :goto_0
    if-ge v3, v1, :cond_1

    .line 32
    .line 33
    int-to-float v4, v3

    .line 34
    add-int/lit8 v5, p2, 0x1

    .line 35
    .line 36
    int-to-float v5, v5

    .line 37
    div-float/2addr v4, v5

    .line 38
    aput v4, v2, v3

    .line 39
    .line 40
    add-int/lit8 v3, v3, 0x1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    move-object p2, v2

    .line 44
    :goto_1
    iput-object p2, p0, Lh2/s9;->g:[F

    .line 45
    .line 46
    new-instance p2, Ll2/g1;

    .line 47
    .line 48
    invoke-direct {p2, v0}, Ll2/g1;-><init>(I)V

    .line 49
    .line 50
    .line 51
    iput-object p2, p0, Lh2/s9;->h:Ll2/g1;

    .line 52
    .line 53
    new-instance p2, Ll2/g1;

    .line 54
    .line 55
    invoke-direct {p2, v0}, Ll2/g1;-><init>(I)V

    .line 56
    .line 57
    .line 58
    iput-object p2, p0, Lh2/s9;->i:Ll2/g1;

    .line 59
    .line 60
    new-instance p2, Ll2/g1;

    .line 61
    .line 62
    invoke-direct {p2, v0}, Ll2/g1;-><init>(I)V

    .line 63
    .line 64
    .line 65
    iput-object p2, p0, Lh2/s9;->k:Ll2/g1;

    .line 66
    .line 67
    new-instance p2, Ll2/g1;

    .line 68
    .line 69
    invoke-direct {p2, v0}, Ll2/g1;-><init>(I)V

    .line 70
    .line 71
    .line 72
    iput-object p2, p0, Lh2/s9;->l:Ll2/g1;

    .line 73
    .line 74
    sget-object p2, Lg1/w1;->e:Lg1/w1;

    .line 75
    .line 76
    iput-object p2, p0, Lh2/s9;->m:Lg1/w1;

    .line 77
    .line 78
    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 79
    .line 80
    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 81
    .line 82
    .line 83
    move-result-object p2

    .line 84
    iput-object p2, p0, Lh2/s9;->n:Ll2/j1;

    .line 85
    .line 86
    new-instance p2, Ld2/g;

    .line 87
    .line 88
    const/16 p3, 0x19

    .line 89
    .line 90
    invoke-direct {p2, p0, p3}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 91
    .line 92
    .line 93
    iput-object p2, p0, Lh2/s9;->o:Ld2/g;

    .line 94
    .line 95
    invoke-interface {p4}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 96
    .line 97
    .line 98
    move-result-object p2

    .line 99
    check-cast p2, Ljava/lang/Number;

    .line 100
    .line 101
    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    .line 102
    .line 103
    .line 104
    move-result p2

    .line 105
    invoke-interface {p4}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 106
    .line 107
    .line 108
    move-result-object p3

    .line 109
    check-cast p3, Ljava/lang/Number;

    .line 110
    .line 111
    invoke-virtual {p3}, Ljava/lang/Number;->floatValue()F

    .line 112
    .line 113
    .line 114
    move-result p3

    .line 115
    const/4 p4, 0x0

    .line 116
    invoke-static {p2, p3, p1, p4, p4}, Lh2/q9;->l(FFFFF)F

    .line 117
    .line 118
    .line 119
    move-result p1

    .line 120
    new-instance p2, Ll2/f1;

    .line 121
    .line 122
    invoke-direct {p2, p1}, Ll2/f1;-><init>(F)V

    .line 123
    .line 124
    .line 125
    iput-object p2, p0, Lh2/s9;->p:Ll2/f1;

    .line 126
    .line 127
    new-instance p1, Ll2/f1;

    .line 128
    .line 129
    invoke-direct {p1, p4}, Ll2/f1;-><init>(F)V

    .line 130
    .line 131
    .line 132
    iput-object p1, p0, Lh2/s9;->q:Ll2/f1;

    .line 133
    .line 134
    new-instance p1, Lg1/a0;

    .line 135
    .line 136
    const/4 p2, 0x1

    .line 137
    invoke-direct {p1, p0, p2}, Lg1/a0;-><init>(Ljava/lang/Object;I)V

    .line 138
    .line 139
    .line 140
    iput-object p1, p0, Lh2/s9;->r:Lg1/a0;

    .line 141
    .line 142
    new-instance p1, Le1/b1;

    .line 143
    .line 144
    invoke-direct {p1}, Le1/b1;-><init>()V

    .line 145
    .line 146
    .line 147
    iput-object p1, p0, Lh2/s9;->s:Le1/b1;

    .line 148
    .line 149
    return-void
.end method


# virtual methods
.method public final a(Le1/e;Lg1/c1;)Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Le1/w0;->d:Le1/w0;

    .line 2
    .line 3
    new-instance v0, Lg60/w;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-direct {v0, p0, p1, v1}, Lg60/w;-><init>(Lh2/s9;Le1/e;Lkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    invoke-static {v0, p2}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 14
    .line 15
    if-ne p0, p1, :cond_0

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    return-object p0
.end method

.method public final b(F)V
    .locals 6

    .line 1
    iget-object v0, p0, Lh2/s9;->m:Lg1/w1;

    .line 2
    .line 3
    sget-object v1, Lg1/w1;->d:Lg1/w1;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/high16 v3, 0x40000000    # 2.0f

    .line 7
    .line 8
    if-ne v0, v1, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Lh2/s9;->i:Ll2/g1;

    .line 11
    .line 12
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    int-to-float v0, v0

    .line 17
    iget-object v1, p0, Lh2/s9;->l:Ll2/g1;

    .line 18
    .line 19
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    int-to-float v4, v4

    .line 24
    div-float/2addr v4, v3

    .line 25
    sub-float/2addr v0, v4

    .line 26
    invoke-static {v0, v2}, Ljava/lang/Math;->max(FF)F

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    int-to-float v1, v1

    .line 35
    div-float/2addr v1, v3

    .line 36
    invoke-static {v1, v0}, Ljava/lang/Math;->min(FF)F

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    iget-object v0, p0, Lh2/s9;->h:Ll2/g1;

    .line 42
    .line 43
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    int-to-float v0, v0

    .line 48
    iget-object v1, p0, Lh2/s9;->k:Ll2/g1;

    .line 49
    .line 50
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 51
    .line 52
    .line 53
    move-result v4

    .line 54
    int-to-float v4, v4

    .line 55
    div-float/2addr v4, v3

    .line 56
    sub-float/2addr v0, v4

    .line 57
    invoke-static {v0, v2}, Ljava/lang/Math;->max(FF)F

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    int-to-float v1, v1

    .line 66
    div-float/2addr v1, v3

    .line 67
    invoke-static {v1, v0}, Ljava/lang/Math;->min(FF)F

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    :goto_0
    iget-object v3, p0, Lh2/s9;->p:Ll2/f1;

    .line 72
    .line 73
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    add-float/2addr v4, p1

    .line 78
    iget-object p1, p0, Lh2/s9;->q:Ll2/f1;

    .line 79
    .line 80
    invoke-virtual {p1}, Ll2/f1;->o()F

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    add-float/2addr v5, v4

    .line 85
    invoke-virtual {v3, v5}, Ll2/f1;->p(F)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p1, v2}, Ll2/f1;->p(F)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 92
    .line 93
    .line 94
    move-result p1

    .line 95
    iget-object v2, p0, Lh2/s9;->g:[F

    .line 96
    .line 97
    invoke-static {v2, p1, v1, v0}, Lh2/q9;->i([FFFF)F

    .line 98
    .line 99
    .line 100
    move-result p1

    .line 101
    iget-object v2, p0, Lh2/s9;->c:Lgy0/f;

    .line 102
    .line 103
    invoke-interface {v2}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 104
    .line 105
    .line 106
    move-result-object v3

    .line 107
    check-cast v3, Ljava/lang/Number;

    .line 108
    .line 109
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 110
    .line 111
    .line 112
    move-result v3

    .line 113
    invoke-interface {v2}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    check-cast v2, Ljava/lang/Number;

    .line 118
    .line 119
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    invoke-static {v1, v0, p1, v3, v2}, Lh2/q9;->l(FFFFF)F

    .line 124
    .line 125
    .line 126
    move-result p1

    .line 127
    iget-object v0, p0, Lh2/s9;->d:Ll2/f1;

    .line 128
    .line 129
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 130
    .line 131
    .line 132
    move-result v0

    .line 133
    cmpg-float v0, p1, v0

    .line 134
    .line 135
    if-nez v0, :cond_1

    .line 136
    .line 137
    return-void

    .line 138
    :cond_1
    iget-object v0, p0, Lh2/s9;->e:Lay0/k;

    .line 139
    .line 140
    if-eqz v0, :cond_2

    .line 141
    .line 142
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    return-void

    .line 150
    :cond_2
    invoke-virtual {p0, p1}, Lh2/s9;->d(F)V

    .line 151
    .line 152
    .line 153
    return-void
.end method

.method public final c()F
    .locals 4

    .line 1
    iget-object v0, p0, Lh2/s9;->c:Lgy0/f;

    .line 2
    .line 3
    invoke-interface {v0}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-interface {v0}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    check-cast v2, Ljava/lang/Number;

    .line 18
    .line 19
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    iget-object p0, p0, Lh2/s9;->d:Ll2/f1;

    .line 24
    .line 25
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    invoke-interface {v0}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    check-cast v3, Ljava/lang/Number;

    .line 34
    .line 35
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    invoke-interface {v0}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    check-cast v0, Ljava/lang/Number;

    .line 44
    .line 45
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    invoke-static {p0, v3, v0}, Lkp/r9;->d(FFF)F

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    invoke-static {v1, v2, p0}, Lh2/q9;->j(FFF)F

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    return p0
.end method

.method public final d(F)V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lh2/s9;->f:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lh2/s9;->c:Lgy0/f;

    .line 6
    .line 7
    invoke-interface {v0}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    check-cast v1, Ljava/lang/Number;

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-interface {v0}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    check-cast v2, Ljava/lang/Number;

    .line 22
    .line 23
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    invoke-static {p1, v1, v2}, Lkp/r9;->d(FFF)F

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    invoke-interface {v0}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    check-cast v1, Ljava/lang/Number;

    .line 36
    .line 37
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    invoke-interface {v0}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    check-cast v0, Ljava/lang/Number;

    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    iget-object v2, p0, Lh2/s9;->g:[F

    .line 52
    .line 53
    invoke-static {v2, p1, v1, v0}, Lh2/q9;->i([FFFF)F

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    :cond_0
    iget-object p0, p0, Lh2/s9;->d:Ll2/f1;

    .line 58
    .line 59
    invoke-virtual {p0, p1}, Ll2/f1;->p(F)V

    .line 60
    .line 61
    .line 62
    return-void
.end method
