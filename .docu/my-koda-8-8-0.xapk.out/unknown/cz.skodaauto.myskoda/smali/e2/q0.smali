.class public final Le2/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt1/w0;


# instance fields
.field public final synthetic a:Le2/w0;


# direct methods
.method public constructor <init>(Le2/w0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le2/q0;->a:Le2/w0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 0

    .line 1
    return-void
.end method

.method public final b(J)V
    .locals 1

    .line 1
    const/4 p1, 0x1

    .line 2
    iget-object p0, p0, Le2/q0;->a:Le2/w0;

    .line 3
    .line 4
    invoke-virtual {p0, p1}, Le2/w0;->k(Z)J

    .line 5
    .line 6
    .line 7
    move-result-wide p1

    .line 8
    invoke-static {p1, p2}, Le2/d0;->a(J)J

    .line 9
    .line 10
    .line 11
    move-result-wide p1

    .line 12
    iget-object v0, p0, Le2/w0;->d:Lt1/p0;

    .line 13
    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    invoke-virtual {v0}, Lt1/p0;->d()Lt1/j1;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {v0, p1, p2}, Lt1/j1;->e(J)J

    .line 24
    .line 25
    .line 26
    move-result-wide p1

    .line 27
    iput-wide p1, p0, Le2/w0;->n:J

    .line 28
    .line 29
    new-instance v0, Ld3/b;

    .line 30
    .line 31
    invoke-direct {v0, p1, p2}, Ld3/b;-><init>(J)V

    .line 32
    .line 33
    .line 34
    iget-object p1, p0, Le2/w0;->r:Ll2/j1;

    .line 35
    .line 36
    invoke-virtual {p1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    const-wide/16 p1, 0x0

    .line 40
    .line 41
    iput-wide p1, p0, Le2/w0;->p:J

    .line 42
    .line 43
    sget-object p1, Lt1/b0;->d:Lt1/b0;

    .line 44
    .line 45
    iget-object p2, p0, Le2/w0;->q:Ll2/j1;

    .line 46
    .line 47
    invoke-virtual {p2, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    const/4 p1, 0x0

    .line 51
    invoke-virtual {p0, p1}, Le2/w0;->s(Z)V

    .line 52
    .line 53
    .line 54
    :cond_1
    :goto_0
    return-void
.end method

.method public final c()V
    .locals 2

    .line 1
    iget-object p0, p0, Le2/q0;->a:Le2/w0;

    .line 2
    .line 3
    iget-object v0, p0, Le2/w0;->q:Ll2/j1;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Le2/w0;->r:Ll2/j1;

    .line 10
    .line 11
    invoke-virtual {p0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final d()V
    .locals 2

    .line 1
    iget-object p0, p0, Le2/q0;->a:Le2/w0;

    .line 2
    .line 3
    iget-object v0, p0, Le2/w0;->q:Ll2/j1;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Le2/w0;->r:Ll2/j1;

    .line 10
    .line 11
    invoke-virtual {p0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final e(J)V
    .locals 4

    .line 1
    iget-object p0, p0, Le2/q0;->a:Le2/w0;

    .line 2
    .line 3
    iget-wide v0, p0, Le2/w0;->p:J

    .line 4
    .line 5
    invoke-static {v0, v1, p1, p2}, Ld3/b;->h(JJ)J

    .line 6
    .line 7
    .line 8
    move-result-wide p1

    .line 9
    iput-wide p1, p0, Le2/w0;->p:J

    .line 10
    .line 11
    iget-object p1, p0, Le2/w0;->d:Lt1/p0;

    .line 12
    .line 13
    if-eqz p1, :cond_3

    .line 14
    .line 15
    invoke-virtual {p1}, Lt1/p0;->d()Lt1/j1;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    if-eqz p1, :cond_3

    .line 20
    .line 21
    iget-wide v0, p0, Le2/w0;->n:J

    .line 22
    .line 23
    iget-wide v2, p0, Le2/w0;->p:J

    .line 24
    .line 25
    invoke-static {v0, v1, v2, v3}, Ld3/b;->h(JJ)J

    .line 26
    .line 27
    .line 28
    move-result-wide v0

    .line 29
    new-instance p2, Ld3/b;

    .line 30
    .line 31
    invoke-direct {p2, v0, v1}, Ld3/b;-><init>(J)V

    .line 32
    .line 33
    .line 34
    iget-object v0, p0, Le2/w0;->r:Ll2/j1;

    .line 35
    .line 36
    invoke-virtual {v0, p2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    iget-object p2, p0, Le2/w0;->b:Ll4/p;

    .line 40
    .line 41
    invoke-virtual {p0}, Le2/w0;->i()Ld3/b;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    iget-wide v0, v0, Ld3/b;->a:J

    .line 49
    .line 50
    const/4 v2, 0x1

    .line 51
    invoke-virtual {p1, v0, v1, v2}, Lt1/j1;->b(JZ)I

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    invoke-interface {p2, p1}, Ll4/p;->E(I)I

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    invoke-static {p1, p1}, Lg4/f0;->b(II)J

    .line 60
    .line 61
    .line 62
    move-result-wide p1

    .line 63
    invoke-virtual {p0}, Le2/w0;->m()Ll4/v;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    iget-wide v0, v0, Ll4/v;->b:J

    .line 68
    .line 69
    invoke-static {p1, p2, v0, v1}, Lg4/o0;->b(JJ)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-eqz v0, :cond_0

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_0
    iget-object v0, p0, Le2/w0;->d:Lt1/p0;

    .line 77
    .line 78
    if-eqz v0, :cond_1

    .line 79
    .line 80
    iget-object v0, v0, Lt1/p0;->q:Ll2/j1;

    .line 81
    .line 82
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    check-cast v0, Ljava/lang/Boolean;

    .line 87
    .line 88
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-nez v0, :cond_1

    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_1
    iget-object v0, p0, Le2/w0;->j:Ll3/a;

    .line 96
    .line 97
    if-eqz v0, :cond_2

    .line 98
    .line 99
    const/16 v1, 0x9

    .line 100
    .line 101
    invoke-interface {v0, v1}, Ll3/a;->a(I)V

    .line 102
    .line 103
    .line 104
    :cond_2
    :goto_0
    iget-object v0, p0, Le2/w0;->c:Lay0/k;

    .line 105
    .line 106
    invoke-virtual {p0}, Le2/w0;->m()Ll4/v;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    iget-object v1, v1, Ll4/v;->a:Lg4/g;

    .line 111
    .line 112
    invoke-static {v1, p1, p2}, Le2/w0;->e(Lg4/g;J)Ll4/v;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    new-instance v0, Lg4/o0;

    .line 120
    .line 121
    invoke-direct {v0, p1, p2}, Lg4/o0;-><init>(J)V

    .line 122
    .line 123
    .line 124
    iput-object v0, p0, Le2/w0;->v:Lg4/o0;

    .line 125
    .line 126
    :cond_3
    :goto_1
    return-void
.end method

.method public final onCancel()V
    .locals 0

    .line 1
    return-void
.end method
