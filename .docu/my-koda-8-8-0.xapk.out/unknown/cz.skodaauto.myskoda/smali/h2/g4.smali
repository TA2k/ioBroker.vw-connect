.class public final Lh2/g4;
.super Lh2/s;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Ll2/j1;

.field public final g:Ll2/j1;

.field public final h:Ll2/j1;


# direct methods
.method public constructor <init>(Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Lgy0/j;ILh2/e8;Ljava/util/Locale;)V
    .locals 0

    .line 1
    invoke-direct {p0, p3, p4, p6, p7}, Lh2/s;-><init>(Ljava/lang/Long;Lgy0/j;Lh2/e8;Ljava/util/Locale;)V

    .line 2
    .line 3
    .line 4
    const/4 p3, 0x0

    .line 5
    invoke-static {p3}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 6
    .line 7
    .line 8
    move-result-object p4

    .line 9
    iput-object p4, p0, Lh2/g4;->f:Ll2/j1;

    .line 10
    .line 11
    invoke-static {p3}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 12
    .line 13
    .line 14
    move-result-object p3

    .line 15
    iput-object p3, p0, Lh2/g4;->g:Ll2/j1;

    .line 16
    .line 17
    invoke-virtual {p0, p1, p2}, Lh2/g4;->i(Ljava/lang/Long;Ljava/lang/Long;)V

    .line 18
    .line 19
    .line 20
    new-instance p1, Lh2/o4;

    .line 21
    .line 22
    invoke-direct {p1, p5}, Lh2/o4;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iput-object p1, p0, Lh2/g4;->h:Ll2/j1;

    .line 30
    .line 31
    return-void
.end method


# virtual methods
.method public final f()I
    .locals 0

    .line 1
    iget-object p0, p0, Lh2/g4;->h:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lh2/o4;

    .line 8
    .line 9
    iget p0, p0, Lh2/o4;->a:I

    .line 10
    .line 11
    return p0
.end method

.method public final g()Ljava/lang/Long;
    .locals 2

    .line 1
    iget-object p0, p0, Lh2/g4;->g:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Li2/y;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    iget-wide v0, p0, Li2/y;->g:J

    .line 12
    .line 13
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return-object p0
.end method

.method public final h()Ljava/lang/Long;
    .locals 2

    .line 1
    iget-object p0, p0, Lh2/g4;->f:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Li2/y;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    iget-wide v0, p0, Li2/y;->g:J

    .line 12
    .line 13
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return-object p0
.end method

.method public final i(Ljava/lang/Long;Ljava/lang/Long;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lh2/s;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lgy0/j;

    .line 4
    .line 5
    iget-object v1, p0, Lh2/s;->c:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Li2/b0;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 13
    .line 14
    .line 15
    move-result-wide v3

    .line 16
    invoke-virtual {v1, v3, v4}, Li2/b0;->a(J)Li2/y;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    iget v3, p1, Li2/y;->d:I

    .line 21
    .line 22
    invoke-virtual {v0, v3}, Lgy0/j;->i(I)Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-eqz v3, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move-object p1, v2

    .line 30
    :goto_0
    if-eqz p2, :cond_1

    .line 31
    .line 32
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 33
    .line 34
    .line 35
    move-result-wide v3

    .line 36
    invoke-virtual {v1, v3, v4}, Li2/b0;->a(J)Li2/y;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    iget v1, p2, Li2/y;->d:I

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Lgy0/j;->i(I)Z

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    if-eqz v0, :cond_1

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    move-object p2, v2

    .line 50
    :goto_1
    iget-object v0, p0, Lh2/g4;->g:Ll2/j1;

    .line 51
    .line 52
    iget-object p0, p0, Lh2/g4;->f:Ll2/j1;

    .line 53
    .line 54
    if-eqz p1, :cond_3

    .line 55
    .line 56
    if-eqz p2, :cond_2

    .line 57
    .line 58
    iget-wide v3, p1, Li2/y;->g:J

    .line 59
    .line 60
    iget-wide v5, p2, Li2/y;->g:J

    .line 61
    .line 62
    cmp-long v1, v3, v5

    .line 63
    .line 64
    if-gtz v1, :cond_3

    .line 65
    .line 66
    :cond_2
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v0, p2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    return-void

    .line 73
    :cond_3
    invoke-virtual {p0, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v0, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    return-void
.end method
