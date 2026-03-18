.class public final Lm1/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg1/e2;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lg1/e2;

.field public final synthetic c:Lg1/q2;


# direct methods
.method public synthetic constructor <init>(Lg1/e2;Lg1/q2;I)V
    .locals 0

    .line 1
    iput p3, p0, Lm1/p;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Lm1/p;->c:Lg1/q2;

    .line 4
    .line 5
    iput-object p1, p0, Lm1/p;->b:Lg1/e2;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(F)F
    .locals 1

    .line 1
    iget v0, p0, Lm1/p;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm1/p;->b:Lg1/e2;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Lg1/e2;->a(F)F

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lm1/p;->b:Lg1/e2;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lg1/e2;->a(F)F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b(I)I
    .locals 10

    .line 1
    iget v0, p0, Lm1/p;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm1/p;->c:Lg1/q2;

    .line 7
    .line 8
    check-cast p0, Lp1/v;

    .line 9
    .line 10
    invoke-virtual {p0}, Lp1/v;->k()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    sub-int/2addr p1, v0

    .line 15
    invoke-virtual {p0}, Lp1/v;->o()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    mul-int/2addr v0, p1

    .line 20
    int-to-float p1, v0

    .line 21
    iget-object v0, p0, Lp1/v;->d:Lh8/o;

    .line 22
    .line 23
    iget-object v0, v0, Lh8/o;->d:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v0, Ll2/f1;

    .line 26
    .line 27
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    invoke-virtual {p0}, Lp1/v;->o()I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    int-to-float v1, v1

    .line 36
    mul-float/2addr v0, v1

    .line 37
    sub-float/2addr p1, v0

    .line 38
    const/4 v0, 0x0

    .line 39
    int-to-float v0, v0

    .line 40
    add-float/2addr p1, v0

    .line 41
    invoke-static {p1}, Lcy0/a;->i(F)I

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    invoke-static {p0}, Ljp/dd;->b(Lp1/v;)J

    .line 46
    .line 47
    .line 48
    move-result-wide v0

    .line 49
    int-to-long v2, p1

    .line 50
    add-long v4, v0, v2

    .line 51
    .line 52
    iget-wide v6, p0, Lp1/v;->h:J

    .line 53
    .line 54
    iget-wide v8, p0, Lp1/v;->g:J

    .line 55
    .line 56
    invoke-static/range {v4 .. v9}, Lkp/r9;->g(JJJ)J

    .line 57
    .line 58
    .line 59
    move-result-wide v0

    .line 60
    invoke-static {p0}, Ljp/dd;->b(Lp1/v;)J

    .line 61
    .line 62
    .line 63
    move-result-wide p0

    .line 64
    sub-long/2addr v0, p0

    .line 65
    long-to-int p0, v0

    .line 66
    return p0

    .line 67
    :pswitch_0
    iget-object v0, p0, Lm1/p;->c:Lg1/q2;

    .line 68
    .line 69
    check-cast v0, Lm1/t;

    .line 70
    .line 71
    invoke-virtual {v0}, Lm1/t;->h()Lm1/l;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    iget-object v1, v0, Lm1/l;->k:Ljava/lang/Object;

    .line 76
    .line 77
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    const/4 v2, 0x0

    .line 82
    if-eqz v1, :cond_0

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_0
    invoke-virtual {p0}, Lm1/p;->c()I

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    invoke-virtual {p0}, Lm1/p;->e()I

    .line 90
    .line 91
    .line 92
    move-result v3

    .line 93
    if-gt p1, v3, :cond_3

    .line 94
    .line 95
    if-gt v1, p1, :cond_3

    .line 96
    .line 97
    iget-object p0, v0, Lm1/l;->k:Ljava/lang/Object;

    .line 98
    .line 99
    move-object v0, p0

    .line 100
    check-cast v0, Ljava/util/Collection;

    .line 101
    .line 102
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 103
    .line 104
    .line 105
    move-result v0

    .line 106
    move v1, v2

    .line 107
    :goto_0
    if-ge v1, v0, :cond_2

    .line 108
    .line 109
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v3

    .line 113
    move-object v4, v3

    .line 114
    check-cast v4, Lm1/m;

    .line 115
    .line 116
    iget v4, v4, Lm1/m;->a:I

    .line 117
    .line 118
    if-ne v4, p1, :cond_1

    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 122
    .line 123
    goto :goto_0

    .line 124
    :cond_2
    const/4 v3, 0x0

    .line 125
    :goto_1
    check-cast v3, Lm1/m;

    .line 126
    .line 127
    if-eqz v3, :cond_4

    .line 128
    .line 129
    iget v2, v3, Lm1/m;->o:I

    .line 130
    .line 131
    goto :goto_2

    .line 132
    :cond_3
    invoke-static {v0}, Lc21/c;->d(Lm1/l;)I

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    invoke-virtual {p0}, Lm1/p;->c()I

    .line 137
    .line 138
    .line 139
    move-result v1

    .line 140
    sub-int/2addr p1, v1

    .line 141
    mul-int/2addr p1, v0

    .line 142
    invoke-virtual {p0}, Lm1/p;->d()I

    .line 143
    .line 144
    .line 145
    move-result p0

    .line 146
    sub-int v2, p1, p0

    .line 147
    .line 148
    :cond_4
    :goto_2
    return v2

    .line 149
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final c()I
    .locals 1

    .line 1
    iget v0, p0, Lm1/p;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm1/p;->c:Lg1/q2;

    .line 7
    .line 8
    check-cast p0, Lp1/v;

    .line 9
    .line 10
    iget p0, p0, Lp1/v;->e:I

    .line 11
    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lm1/p;->c:Lg1/q2;

    .line 14
    .line 15
    check-cast p0, Lm1/t;

    .line 16
    .line 17
    iget-object p0, p0, Lm1/t;->e:Lm1/o;

    .line 18
    .line 19
    iget-object p0, p0, Lm1/o;->b:Ll2/g1;

    .line 20
    .line 21
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final d()I
    .locals 1

    .line 1
    iget v0, p0, Lm1/p;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm1/p;->c:Lg1/q2;

    .line 7
    .line 8
    check-cast p0, Lp1/v;

    .line 9
    .line 10
    iget p0, p0, Lp1/v;->f:I

    .line 11
    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lm1/p;->c:Lg1/q2;

    .line 14
    .line 15
    check-cast p0, Lm1/t;

    .line 16
    .line 17
    iget-object p0, p0, Lm1/t;->e:Lm1/o;

    .line 18
    .line 19
    iget-object p0, p0, Lm1/o;->c:Ll2/g1;

    .line 20
    .line 21
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final e()I
    .locals 1

    .line 1
    iget v0, p0, Lm1/p;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm1/p;->c:Lg1/q2;

    .line 7
    .line 8
    check-cast p0, Lp1/v;

    .line 9
    .line 10
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    iget-object p0, p0, Lp1/o;->a:Ljava/util/List;

    .line 15
    .line 16
    invoke-static {p0}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Lp1/d;

    .line 21
    .line 22
    iget p0, p0, Lp1/d;->a:I

    .line 23
    .line 24
    return p0

    .line 25
    :pswitch_0
    iget-object p0, p0, Lm1/p;->c:Lg1/q2;

    .line 26
    .line 27
    check-cast p0, Lm1/t;

    .line 28
    .line 29
    invoke-virtual {p0}, Lm1/t;->h()Lm1/l;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    iget-object p0, p0, Lm1/l;->k:Ljava/lang/Object;

    .line 34
    .line 35
    invoke-static {p0}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    check-cast p0, Lm1/m;

    .line 40
    .line 41
    if-eqz p0, :cond_0

    .line 42
    .line 43
    iget p0, p0, Lm1/m;->a:I

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    const/4 p0, 0x0

    .line 47
    :goto_0
    return p0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final f(II)V
    .locals 1

    .line 1
    iget v0, p0, Lm1/p;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    int-to-float p2, p2

    .line 7
    iget-object p0, p0, Lm1/p;->c:Lg1/q2;

    .line 8
    .line 9
    check-cast p0, Lp1/v;

    .line 10
    .line 11
    invoke-virtual {p0}, Lp1/v;->o()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    int-to-float v0, v0

    .line 16
    div-float/2addr p2, v0

    .line 17
    const/4 v0, 0x1

    .line 18
    invoke-virtual {p0, p1, p2, v0}, Lp1/v;->u(IFZ)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :pswitch_0
    iget-object p0, p0, Lm1/p;->c:Lg1/q2;

    .line 23
    .line 24
    check-cast p0, Lm1/t;

    .line 25
    .line 26
    const/4 v0, 0x1

    .line 27
    invoke-virtual {p0, p1, p2, v0}, Lm1/t;->k(IIZ)V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
