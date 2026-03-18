.class public final Lh2/r8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Z

.field public final b:Lay0/k;

.field public final c:Z

.field public d:Lc1/j;

.field public final e:Li2/p;

.field public f:Lc1/a0;

.field public g:Lc1/a0;


# direct methods
.method public constructor <init>(ZLay0/a;Lay0/a;Lh2/s8;Lay0/k;Z)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lh2/r8;->a:Z

    .line 5
    .line 6
    iput-object p5, p0, Lh2/r8;->b:Lay0/k;

    .line 7
    .line 8
    iput-boolean p6, p0, Lh2/r8;->c:Z

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    sget-object p1, Lh2/s8;->f:Lh2/s8;

    .line 13
    .line 14
    if-eq p4, p1, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 18
    .line 19
    const-string p1, "The initial value must not be set to PartiallyExpanded if skipPartiallyExpanded is set to true."

    .line 20
    .line 21
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :cond_1
    :goto_0
    if-eqz p6, :cond_3

    .line 26
    .line 27
    sget-object p1, Lh2/s8;->d:Lh2/s8;

    .line 28
    .line 29
    if-eq p4, p1, :cond_2

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 33
    .line 34
    const-string p1, "The initial value must not be set to Hidden if skipHiddenState is set to true."

    .line 35
    .line 36
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :cond_3
    :goto_1
    sget-object p1, Lh2/m8;->b:Lc1/a2;

    .line 41
    .line 42
    iput-object p1, p0, Lh2/r8;->d:Lc1/j;

    .line 43
    .line 44
    new-instance v0, Li2/p;

    .line 45
    .line 46
    new-instance v2, Lh2/n8;

    .line 47
    .line 48
    const/4 p1, 0x0

    .line 49
    invoke-direct {v2, p2, p1}, Lh2/n8;-><init>(Lay0/a;I)V

    .line 50
    .line 51
    .line 52
    new-instance v4, Ld2/g;

    .line 53
    .line 54
    const/16 p1, 0x18

    .line 55
    .line 56
    invoke-direct {v4, p0, p1}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 57
    .line 58
    .line 59
    move-object v3, p3

    .line 60
    move-object v1, p4

    .line 61
    move-object v5, p5

    .line 62
    invoke-direct/range {v0 .. v5}, Li2/p;-><init>(Lh2/s8;Lh2/n8;Lay0/a;Ld2/g;Lay0/k;)V

    .line 63
    .line 64
    .line 65
    iput-object v0, p0, Lh2/r8;->e:Li2/p;

    .line 66
    .line 67
    invoke-static {}, Lc1/d;->s()Lc1/d1;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    iput-object p1, p0, Lh2/r8;->f:Lc1/a0;

    .line 72
    .line 73
    invoke-static {}, Lc1/d;->s()Lc1/d1;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    iput-object p1, p0, Lh2/r8;->g:Lc1/a0;

    .line 78
    .line 79
    return-void
.end method

.method public static a(Lh2/r8;Lh2/s8;Lc1/a0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lh2/r8;->e:Li2/p;

    .line 2
    .line 3
    iget-object v0, v0, Li2/p;->k:Ll2/f1;

    .line 4
    .line 5
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-object v1, p0, Lh2/r8;->e:Li2/p;

    .line 10
    .line 11
    new-instance v2, Lh2/q8;

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-direct {v2, p0, v0, p2, v3}, Lh2/q8;-><init>(Lh2/r8;FLc1/a0;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    sget-object p0, Le1/w0;->d:Le1/w0;

    .line 18
    .line 19
    invoke-virtual {v1, p1, p0, v2, p3}, Li2/p;->b(Ljava/lang/Object;Le1/w0;Lay0/p;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 24
    .line 25
    if-ne p0, p1, :cond_0

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0
.end method


# virtual methods
.method public final b(Lrx0/i;)Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Lh2/s8;->e:Lh2/s8;

    .line 2
    .line 3
    iget-object v1, p0, Lh2/r8;->b:Lay0/k;

    .line 4
    .line 5
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    check-cast v1, Ljava/lang/Boolean;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    iget-object v1, p0, Lh2/r8;->f:Lc1/a0;

    .line 18
    .line 19
    invoke-static {p0, v0, v1, p1}, Lh2/r8;->a(Lh2/r8;Lh2/s8;Lc1/a0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 24
    .line 25
    if-ne p0, p1, :cond_0

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0
.end method

.method public final c()Lh2/s8;
    .locals 0

    .line 1
    iget-object p0, p0, Lh2/r8;->e:Li2/p;

    .line 2
    .line 3
    iget-object p0, p0, Li2/p;->g:Ll2/j1;

    .line 4
    .line 5
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lh2/s8;

    .line 10
    .line 11
    return-object p0
.end method

.method public final d(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-boolean v0, p0, Lh2/r8;->c:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    sget-object v0, Lh2/s8;->d:Lh2/s8;

    .line 6
    .line 7
    iget-object v1, p0, Lh2/r8;->b:Lay0/k;

    .line 8
    .line 9
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    iget-object v1, p0, Lh2/r8;->g:Lc1/a0;

    .line 22
    .line 23
    invoke-static {p0, v0, v1, p1}, Lh2/r8;->a(Lh2/r8;Lh2/s8;Lc1/a0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    if-ne p0, p1, :cond_0

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0

    .line 35
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 36
    .line 37
    const-string p1, "Attempted to animate to hidden when skipHiddenState was enabled. Set skipHiddenState to false to use this function."

    .line 38
    .line 39
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0
.end method

.method public final e()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lh2/r8;->e:Li2/p;

    .line 2
    .line 3
    iget-object p0, p0, Li2/p;->g:Ll2/j1;

    .line 4
    .line 5
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    sget-object v0, Lh2/s8;->d:Lh2/s8;

    .line 10
    .line 11
    if-eq p0, v0, :cond_0

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

.method public final f(Lrx0/i;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-boolean v0, p0, Lh2/r8;->a:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    sget-object v0, Lh2/s8;->f:Lh2/s8;

    .line 6
    .line 7
    iget-object v1, p0, Lh2/r8;->b:Lay0/k;

    .line 8
    .line 9
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    iget-object v1, p0, Lh2/r8;->g:Lc1/a0;

    .line 22
    .line 23
    invoke-static {p0, v0, v1, p1}, Lh2/r8;->a(Lh2/r8;Lh2/s8;Lc1/a0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    if-ne p0, p1, :cond_0

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0

    .line 35
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 36
    .line 37
    const-string p1, "Attempted to animate to partial expanded when skipPartiallyExpanded was enabled. Set skipPartiallyExpanded to false to use this function."

    .line 38
    .line 39
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0
.end method

.method public final g(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lh2/r8;->e:Li2/p;

    .line 2
    .line 3
    invoke-virtual {v0}, Li2/p;->d()Li2/u0;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Lh2/s8;->f:Lh2/s8;

    .line 8
    .line 9
    iget-object v0, v0, Li2/u0;->a:Ljava/util/Map;

    .line 10
    .line 11
    invoke-interface {v0, v1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    sget-object v1, Lh2/s8;->e:Lh2/s8;

    .line 19
    .line 20
    :goto_0
    iget-object v0, p0, Lh2/r8;->b:Lay0/k;

    .line 21
    .line 22
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    check-cast v0, Ljava/lang/Boolean;

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_1

    .line 33
    .line 34
    iget-object v0, p0, Lh2/r8;->f:Lc1/a0;

    .line 35
    .line 36
    invoke-static {p0, v1, v0, p1}, Lh2/r8;->a(Lh2/r8;Lh2/s8;Lc1/a0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 41
    .line 42
    if-ne p0, p1, :cond_1

    .line 43
    .line 44
    return-object p0

    .line 45
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    return-object p0
.end method
