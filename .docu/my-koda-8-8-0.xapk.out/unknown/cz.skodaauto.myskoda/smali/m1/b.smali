.class public final Lm1/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo1/r0;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Z

.field public final synthetic c:Lg1/q2;


# direct methods
.method public synthetic constructor <init>(Lg1/q2;ZI)V
    .locals 0

    .line 1
    iput p3, p0, Lm1/b;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lm1/b;->c:Lg1/q2;

    .line 4
    .line 5
    iput-boolean p2, p0, Lm1/b;->b:Z

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 1

    .line 1
    iget v0, p0, Lm1/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm1/b;->c:Lg1/q2;

    .line 7
    .line 8
    check-cast p0, Lp1/v;

    .line 9
    .line 10
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget v0, v0, Lp1/o;->f:I

    .line 15
    .line 16
    neg-int v0, v0

    .line 17
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    iget p0, p0, Lp1/o;->d:I

    .line 22
    .line 23
    :goto_0
    add-int/2addr v0, p0

    .line 24
    return v0

    .line 25
    :pswitch_0
    iget-object p0, p0, Lm1/b;->c:Lg1/q2;

    .line 26
    .line 27
    check-cast p0, Lm1/t;

    .line 28
    .line 29
    invoke-virtual {p0}, Lm1/t;->h()Lm1/l;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    iget v0, v0, Lm1/l;->l:I

    .line 34
    .line 35
    neg-int v0, v0

    .line 36
    invoke-virtual {p0}, Lm1/t;->h()Lm1/l;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    iget p0, p0, Lm1/l;->p:I

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b()F
    .locals 2

    .line 1
    iget v0, p0, Lm1/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm1/b;->c:Lg1/q2;

    .line 7
    .line 8
    check-cast p0, Lp1/v;

    .line 9
    .line 10
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {p0}, Lp1/v;->m()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    invoke-static {v0, p0}, Lp1/y;->a(Lp1/o;I)J

    .line 19
    .line 20
    .line 21
    move-result-wide v0

    .line 22
    long-to-float p0, v0

    .line 23
    return p0

    .line 24
    :pswitch_0
    iget-object p0, p0, Lm1/b;->c:Lg1/q2;

    .line 25
    .line 26
    check-cast p0, Lm1/t;

    .line 27
    .line 28
    iget-object v0, p0, Lm1/t;->e:Lm1/o;

    .line 29
    .line 30
    iget-object v0, v0, Lm1/o;->b:Ll2/g1;

    .line 31
    .line 32
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget-object v1, p0, Lm1/t;->e:Lm1/o;

    .line 37
    .line 38
    iget-object v1, v1, Lm1/o;->c:Ll2/g1;

    .line 39
    .line 40
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    invoke-virtual {p0}, Lm1/t;->d()Z

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    if-eqz p0, :cond_0

    .line 49
    .line 50
    mul-int/lit16 v0, v0, 0x1f4

    .line 51
    .line 52
    add-int/2addr v0, v1

    .line 53
    int-to-float p0, v0

    .line 54
    const/16 v0, 0x64

    .line 55
    .line 56
    int-to-float v0, v0

    .line 57
    add-float/2addr p0, v0

    .line 58
    goto :goto_0

    .line 59
    :cond_0
    mul-int/lit16 v0, v0, 0x1f4

    .line 60
    .line 61
    add-int/2addr v0, v1

    .line 62
    int-to-float p0, v0

    .line 63
    :goto_0
    return p0

    .line 64
    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final c()Ld4/b;
    .locals 2

    .line 1
    iget v0, p0, Lm1/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lm1/b;->c:Lg1/q2;

    .line 7
    .line 8
    check-cast v0, Lp1/v;

    .line 9
    .line 10
    iget-boolean p0, p0, Lm1/b;->b:Z

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    new-instance p0, Ld4/b;

    .line 16
    .line 17
    invoke-virtual {v0}, Lp1/v;->m()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    invoke-direct {p0, v0, v1}, Ld4/b;-><init>(II)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, Ld4/b;

    .line 26
    .line 27
    invoke-virtual {v0}, Lp1/v;->m()I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    invoke-direct {p0, v1, v0}, Ld4/b;-><init>(II)V

    .line 32
    .line 33
    .line 34
    :goto_0
    return-object p0

    .line 35
    :pswitch_0
    iget-object v0, p0, Lm1/b;->c:Lg1/q2;

    .line 36
    .line 37
    check-cast v0, Lm1/t;

    .line 38
    .line 39
    iget-boolean p0, p0, Lm1/b;->b:Z

    .line 40
    .line 41
    const/4 v1, 0x1

    .line 42
    if-eqz p0, :cond_1

    .line 43
    .line 44
    new-instance p0, Ld4/b;

    .line 45
    .line 46
    invoke-virtual {v0}, Lm1/t;->h()Lm1/l;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    iget v0, v0, Lm1/l;->n:I

    .line 51
    .line 52
    invoke-direct {p0, v0, v1}, Ld4/b;-><init>(II)V

    .line 53
    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_1
    new-instance p0, Ld4/b;

    .line 57
    .line 58
    invoke-virtual {v0}, Lm1/t;->h()Lm1/l;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    iget v0, v0, Lm1/l;->n:I

    .line 63
    .line 64
    invoke-direct {p0, v1, v0}, Ld4/b;-><init>(II)V

    .line 65
    .line 66
    .line 67
    :goto_1
    return-object p0

    .line 68
    nop

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final d()I
    .locals 4

    .line 1
    iget v0, p0, Lm1/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm1/b;->c:Lg1/q2;

    .line 7
    .line 8
    check-cast p0, Lp1/v;

    .line 9
    .line 10
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget-object v0, v0, Lp1/o;->e:Lg1/w1;

    .line 15
    .line 16
    sget-object v1, Lg1/w1;->d:Lg1/w1;

    .line 17
    .line 18
    if-ne v0, v1, :cond_0

    .line 19
    .line 20
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {p0}, Lp1/o;->e()J

    .line 25
    .line 26
    .line 27
    move-result-wide v0

    .line 28
    const-wide v2, 0xffffffffL

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    and-long/2addr v0, v2

    .line 34
    :goto_0
    long-to-int p0, v0

    .line 35
    goto :goto_1

    .line 36
    :cond_0
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-virtual {p0}, Lp1/o;->e()J

    .line 41
    .line 42
    .line 43
    move-result-wide v0

    .line 44
    const/16 p0, 0x20

    .line 45
    .line 46
    shr-long/2addr v0, p0

    .line 47
    goto :goto_0

    .line 48
    :goto_1
    return p0

    .line 49
    :pswitch_0
    iget-object p0, p0, Lm1/b;->c:Lg1/q2;

    .line 50
    .line 51
    check-cast p0, Lm1/t;

    .line 52
    .line 53
    invoke-virtual {p0}, Lm1/t;->h()Lm1/l;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    iget-object v0, v0, Lm1/l;->o:Lg1/w1;

    .line 58
    .line 59
    sget-object v1, Lg1/w1;->d:Lg1/w1;

    .line 60
    .line 61
    if-ne v0, v1, :cond_1

    .line 62
    .line 63
    invoke-virtual {p0}, Lm1/t;->h()Lm1/l;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-virtual {p0}, Lm1/l;->e()J

    .line 68
    .line 69
    .line 70
    move-result-wide v0

    .line 71
    const-wide v2, 0xffffffffL

    .line 72
    .line 73
    .line 74
    .line 75
    .line 76
    and-long/2addr v0, v2

    .line 77
    :goto_2
    long-to-int p0, v0

    .line 78
    goto :goto_3

    .line 79
    :cond_1
    invoke-virtual {p0}, Lm1/t;->h()Lm1/l;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-virtual {p0}, Lm1/l;->e()J

    .line 84
    .line 85
    .line 86
    move-result-wide v0

    .line 87
    const/16 p0, 0x20

    .line 88
    .line 89
    shr-long/2addr v0, p0

    .line 90
    goto :goto_2

    .line 91
    :goto_3
    return p0

    .line 92
    nop

    .line 93
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final e()F
    .locals 2

    .line 1
    iget v0, p0, Lm1/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm1/b;->c:Lg1/q2;

    .line 7
    .line 8
    check-cast p0, Lp1/v;

    .line 9
    .line 10
    invoke-static {p0}, Ljp/dd;->b(Lp1/v;)J

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    long-to-float p0, v0

    .line 15
    return p0

    .line 16
    :pswitch_0
    iget-object p0, p0, Lm1/b;->c:Lg1/q2;

    .line 17
    .line 18
    check-cast p0, Lm1/t;

    .line 19
    .line 20
    iget-object v0, p0, Lm1/t;->e:Lm1/o;

    .line 21
    .line 22
    iget-object v0, v0, Lm1/o;->b:Ll2/g1;

    .line 23
    .line 24
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object p0, p0, Lm1/t;->e:Lm1/o;

    .line 29
    .line 30
    iget-object p0, p0, Lm1/o;->c:Ll2/g1;

    .line 31
    .line 32
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    mul-int/lit16 v0, v0, 0x1f4

    .line 37
    .line 38
    add-int/2addr v0, p0

    .line 39
    int-to-float p0, v0

    .line 40
    return p0

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final f(ILg90/b;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lm1/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm1/b;->c:Lg1/q2;

    .line 7
    .line 8
    check-cast p0, Lp1/v;

    .line 9
    .line 10
    invoke-static {p0, p1, p2}, Lp1/v;->t(Lp1/v;ILrx0/i;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    if-ne p0, p1, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    :goto_0
    return-object p0

    .line 22
    :pswitch_0
    iget-object p0, p0, Lm1/b;->c:Lg1/q2;

    .line 23
    .line 24
    check-cast p0, Lm1/t;

    .line 25
    .line 26
    invoke-static {p0, p1, p2}, Lm1/t;->j(Lm1/t;ILrx0/i;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    if-ne p0, p1, :cond_1

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    :goto_1
    return-object p0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
