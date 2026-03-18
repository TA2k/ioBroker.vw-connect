.class public final Lc1/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lc1/b2;

.field public final b:Ljava/lang/Object;

.field public final c:Lc1/k;

.field public final d:Ll2/j1;

.field public final e:Ll2/j1;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public final h:Lc1/r0;

.field public final i:Lc1/f1;

.field public final j:Lc1/p;

.field public final k:Lc1/p;

.field public l:Lc1/p;

.field public m:Lc1/p;


# direct methods
.method public constructor <init>(Ljava/lang/Object;Lc1/b2;Ljava/lang/Object;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p2, p0, Lc1/c;->a:Lc1/b2;

    .line 3
    iput-object p3, p0, Lc1/c;->b:Ljava/lang/Object;

    .line 4
    new-instance v0, Lc1/k;

    const/4 v1, 0x0

    const/16 v2, 0x3c

    invoke-direct {v0, p2, p1, v1, v2}, Lc1/k;-><init>(Lc1/b2;Ljava/lang/Object;Lc1/p;I)V

    iput-object v0, p0, Lc1/c;->c:Lc1/k;

    .line 5
    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    move-result-object p2

    iput-object p2, p0, Lc1/c;->d:Ll2/j1;

    .line 6
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    move-result-object p1

    iput-object p1, p0, Lc1/c;->e:Ll2/j1;

    .line 7
    new-instance p1, Lc1/r0;

    invoke-direct {p1}, Lc1/r0;-><init>()V

    iput-object p1, p0, Lc1/c;->h:Lc1/r0;

    .line 8
    new-instance p1, Lc1/f1;

    const/4 p2, 0x3

    invoke-direct {p1, p3, p2}, Lc1/f1;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Lc1/c;->i:Lc1/f1;

    .line 9
    iget-object p1, v0, Lc1/k;->f:Lc1/p;

    .line 10
    instance-of p2, p1, Lc1/l;

    if-eqz p2, :cond_0

    sget-object p3, Lc1/d;->e:Lc1/l;

    goto :goto_0

    .line 11
    :cond_0
    instance-of p3, p1, Lc1/m;

    if-eqz p3, :cond_1

    sget-object p3, Lc1/d;->f:Lc1/m;

    goto :goto_0

    .line 12
    :cond_1
    instance-of p3, p1, Lc1/n;

    if-eqz p3, :cond_2

    sget-object p3, Lc1/d;->g:Lc1/n;

    goto :goto_0

    .line 13
    :cond_2
    sget-object p3, Lc1/d;->h:Lc1/o;

    .line 14
    :goto_0
    iput-object p3, p0, Lc1/c;->j:Lc1/p;

    if-eqz p2, :cond_3

    .line 15
    sget-object p1, Lc1/d;->a:Lc1/l;

    goto :goto_1

    .line 16
    :cond_3
    instance-of p2, p1, Lc1/m;

    if-eqz p2, :cond_4

    sget-object p1, Lc1/d;->b:Lc1/m;

    goto :goto_1

    .line 17
    :cond_4
    instance-of p1, p1, Lc1/n;

    if-eqz p1, :cond_5

    sget-object p1, Lc1/d;->c:Lc1/n;

    goto :goto_1

    .line 18
    :cond_5
    sget-object p1, Lc1/d;->d:Lc1/o;

    .line 19
    :goto_1
    iput-object p1, p0, Lc1/c;->k:Lc1/p;

    .line 20
    iput-object p3, p0, Lc1/c;->l:Lc1/p;

    .line 21
    iput-object p1, p0, Lc1/c;->m:Lc1/p;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Lc1/b2;Ljava/lang/Object;I)V
    .locals 0

    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_0

    const/4 p3, 0x0

    .line 22
    :cond_0
    invoke-direct {p0, p1, p2, p3}, Lc1/c;-><init>(Ljava/lang/Object;Lc1/b2;Ljava/lang/Object;)V

    return-void
.end method

.method public static final a(Lc1/c;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lc1/c;->c:Lc1/k;

    .line 2
    .line 3
    iget-object v1, v0, Lc1/k;->f:Lc1/p;

    .line 4
    .line 5
    invoke-virtual {v1}, Lc1/p;->d()V

    .line 6
    .line 7
    .line 8
    const-wide/high16 v1, -0x8000000000000000L

    .line 9
    .line 10
    iput-wide v1, v0, Lc1/k;->g:J

    .line 11
    .line 12
    iget-object p0, p0, Lc1/c;->d:Ll2/j1;

    .line 13
    .line 14
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public static b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;
    .locals 10

    .line 1
    and-int/lit8 v0, p6, 0x2

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p2, p0, Lc1/c;->i:Lc1/f1;

    .line 6
    .line 7
    :cond_0
    move-object v1, p2

    .line 8
    and-int/lit8 p2, p6, 0x4

    .line 9
    .line 10
    if-eqz p2, :cond_1

    .line 11
    .line 12
    iget-object p2, p0, Lc1/c;->a:Lc1/b2;

    .line 13
    .line 14
    iget-object p2, p2, Lc1/b2;->b:Lay0/k;

    .line 15
    .line 16
    iget-object p3, p0, Lc1/c;->c:Lc1/k;

    .line 17
    .line 18
    iget-object p3, p3, Lc1/k;->f:Lc1/p;

    .line 19
    .line 20
    invoke-interface {p2, p3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p3

    .line 24
    :cond_1
    and-int/lit8 p2, p6, 0x8

    .line 25
    .line 26
    if-eqz p2, :cond_2

    .line 27
    .line 28
    const/4 p4, 0x0

    .line 29
    :cond_2
    move-object v8, p4

    .line 30
    invoke-virtual {p0}, Lc1/c;->d()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    iget-object v2, p0, Lc1/c;->a:Lc1/b2;

    .line 35
    .line 36
    new-instance v0, Lc1/n1;

    .line 37
    .line 38
    iget-object p2, v2, Lc1/b2;->a:Lay0/k;

    .line 39
    .line 40
    invoke-interface {p2, p3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p2

    .line 44
    move-object v5, p2

    .line 45
    check-cast v5, Lc1/p;

    .line 46
    .line 47
    move-object v4, p1

    .line 48
    invoke-direct/range {v0 .. v5}, Lc1/n1;-><init>(Lc1/j;Lc1/b2;Ljava/lang/Object;Ljava/lang/Object;Lc1/p;)V

    .line 49
    .line 50
    .line 51
    iget-object p1, p0, Lc1/c;->c:Lc1/k;

    .line 52
    .line 53
    iget-wide v6, p1, Lc1/k;->g:J

    .line 54
    .line 55
    iget-object p1, p0, Lc1/c;->h:Lc1/r0;

    .line 56
    .line 57
    new-instance v2, Lc1/a;

    .line 58
    .line 59
    const/4 v9, 0x0

    .line 60
    move-object v3, p0

    .line 61
    move-object v4, p3

    .line 62
    move-object v5, v0

    .line 63
    invoke-direct/range {v2 .. v9}, Lc1/a;-><init>(Lc1/c;Ljava/lang/Object;Lc1/f;JLay0/k;Lkotlin/coroutines/Continuation;)V

    .line 64
    .line 65
    .line 66
    invoke-static {p1, v2, p5}, Lc1/r0;->a(Lc1/r0;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0
.end method


# virtual methods
.method public final c(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Lc1/c;->l:Lc1/p;

    .line 2
    .line 3
    iget-object v1, p0, Lc1/c;->j:Lc1/p;

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object v0, p0, Lc1/c;->m:Lc1/p;

    .line 12
    .line 13
    iget-object v1, p0, Lc1/c;->k:Lc1/p;

    .line 14
    .line 15
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_0
    iget-object v0, p0, Lc1/c;->a:Lc1/b2;

    .line 23
    .line 24
    iget-object v1, v0, Lc1/b2;->a:Lay0/k;

    .line 25
    .line 26
    invoke-interface {v1, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Lc1/p;

    .line 31
    .line 32
    invoke-virtual {v1}, Lc1/p;->b()I

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    const/4 v3, 0x0

    .line 37
    move v4, v3

    .line 38
    :goto_0
    if-ge v3, v2, :cond_3

    .line 39
    .line 40
    invoke-virtual {v1, v3}, Lc1/p;->a(I)F

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    iget-object v6, p0, Lc1/c;->l:Lc1/p;

    .line 45
    .line 46
    invoke-virtual {v6, v3}, Lc1/p;->a(I)F

    .line 47
    .line 48
    .line 49
    move-result v6

    .line 50
    cmpg-float v5, v5, v6

    .line 51
    .line 52
    if-ltz v5, :cond_1

    .line 53
    .line 54
    invoke-virtual {v1, v3}, Lc1/p;->a(I)F

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    iget-object v6, p0, Lc1/c;->m:Lc1/p;

    .line 59
    .line 60
    invoke-virtual {v6, v3}, Lc1/p;->a(I)F

    .line 61
    .line 62
    .line 63
    move-result v6

    .line 64
    cmpl-float v5, v5, v6

    .line 65
    .line 66
    if-lez v5, :cond_2

    .line 67
    .line 68
    :cond_1
    invoke-virtual {v1, v3}, Lc1/p;->a(I)F

    .line 69
    .line 70
    .line 71
    move-result v4

    .line 72
    iget-object v5, p0, Lc1/c;->l:Lc1/p;

    .line 73
    .line 74
    invoke-virtual {v5, v3}, Lc1/p;->a(I)F

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    iget-object v6, p0, Lc1/c;->m:Lc1/p;

    .line 79
    .line 80
    invoke-virtual {v6, v3}, Lc1/p;->a(I)F

    .line 81
    .line 82
    .line 83
    move-result v6

    .line 84
    invoke-static {v4, v5, v6}, Lkp/r9;->d(FFF)F

    .line 85
    .line 86
    .line 87
    move-result v4

    .line 88
    invoke-virtual {v1, v3, v4}, Lc1/p;->e(IF)V

    .line 89
    .line 90
    .line 91
    const/4 v4, 0x1

    .line 92
    :cond_2
    add-int/lit8 v3, v3, 0x1

    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_3
    if-eqz v4, :cond_4

    .line 96
    .line 97
    iget-object p0, v0, Lc1/b2;->b:Lay0/k;

    .line 98
    .line 99
    invoke-interface {p0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0

    .line 104
    :cond_4
    :goto_1
    return-object p1
.end method

.method public final d()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/c;->c:Lc1/k;

    .line 2
    .line 3
    iget-object p0, p0, Lc1/k;->e:Ll2/j1;

    .line 4
    .line 5
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final e()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/c;->d:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Lc1/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v2, p0, p1, v1}, Lc1/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lc1/c;->h:Lc1/r0;

    .line 9
    .line 10
    invoke-static {p0, v0, p2}, Lc1/r0;->a(Lc1/r0;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    return-object p0

    .line 19
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0
.end method

.method public final g(Lrx0/c;)Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Lbq0/i;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x2

    .line 5
    invoke-direct {v0, p0, v1, v2}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lc1/c;->h:Lc1/r0;

    .line 9
    .line 10
    invoke-static {p0, v0, p1}, Lc1/r0;->a(Lc1/r0;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    return-object p0

    .line 19
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0
.end method
