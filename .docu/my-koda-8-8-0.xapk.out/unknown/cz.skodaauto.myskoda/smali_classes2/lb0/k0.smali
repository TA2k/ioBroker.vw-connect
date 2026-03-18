.class public final Llb0/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/m;

.field public final b:Ljb0/x;

.field public final c:Lsf0/a;

.field public final d:Lkf0/j0;

.field public final e:Lko0/f;

.field public final f:Lwq0/e0;

.field public final g:Ljr0/f;


# direct methods
.method public constructor <init>(Lkf0/m;Ljb0/x;Lsf0/a;Lkf0/j0;Lko0/f;Lwq0/e0;Ljr0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llb0/k0;->a:Lkf0/m;

    .line 5
    .line 6
    iput-object p2, p0, Llb0/k0;->b:Ljb0/x;

    .line 7
    .line 8
    iput-object p3, p0, Llb0/k0;->c:Lsf0/a;

    .line 9
    .line 10
    iput-object p4, p0, Llb0/k0;->d:Lkf0/j0;

    .line 11
    .line 12
    iput-object p5, p0, Llb0/k0;->e:Lko0/f;

    .line 13
    .line 14
    iput-object p6, p0, Llb0/k0;->f:Lwq0/e0;

    .line 15
    .line 16
    iput-object p7, p0, Llb0/k0;->g:Ljr0/f;

    .line 17
    .line 18
    return-void
.end method

.method public static final a(Llb0/k0;Lss0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Llb0/i0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Llb0/i0;

    .line 7
    .line 8
    iget v1, v0, Llb0/i0;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Llb0/i0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Llb0/i0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Llb0/i0;-><init>(Llb0/k0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Llb0/i0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Llb0/i0;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Llb0/i0;->d:Lss0/k;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object p0, p0, Llb0/k0;->f:Lwq0/e0;

    .line 54
    .line 55
    sget-object p2, Lyq0/n;->j:Lyq0/n;

    .line 56
    .line 57
    iput-object p1, v0, Llb0/i0;->d:Lss0/k;

    .line 58
    .line 59
    iput v3, v0, Llb0/i0;->g:I

    .line 60
    .line 61
    invoke-virtual {p0, p2, v0}, Lwq0/e0;->b(Lyq0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    if-ne p2, v1, :cond_3

    .line 66
    .line 67
    return-object v1

    .line 68
    :cond_3
    :goto_1
    check-cast p2, Lne0/t;

    .line 69
    .line 70
    instance-of p0, p2, Lne0/c;

    .line 71
    .line 72
    if-eqz p0, :cond_4

    .line 73
    .line 74
    check-cast p2, Lne0/c;

    .line 75
    .line 76
    return-object p2

    .line 77
    :cond_4
    instance-of p0, p2, Lne0/e;

    .line 78
    .line 79
    if-eqz p0, :cond_5

    .line 80
    .line 81
    check-cast p2, Lne0/e;

    .line 82
    .line 83
    iget-object p0, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast p0, Lyq0/k;

    .line 86
    .line 87
    iget-object p0, p0, Lyq0/k;->a:Ljava/lang/String;

    .line 88
    .line 89
    new-instance p2, Lne0/e;

    .line 90
    .line 91
    new-instance v0, Lyq0/k;

    .line 92
    .line 93
    invoke-direct {v0, p0}, Lyq0/k;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    new-instance p0, Llx0/l;

    .line 97
    .line 98
    invoke-direct {p0, p1, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    invoke-direct {p2, p0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    return-object p2

    .line 105
    :cond_5
    new-instance p0, La8/r0;

    .line 106
    .line 107
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 108
    .line 109
    .line 110
    throw p0
.end method


# virtual methods
.method public final b(Llb0/h0;)Lyy0/m1;
    .locals 4

    .line 1
    iget-object v0, p0, Llb0/k0;->a:Lkf0/m;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Llb0/j0;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-direct {v1, p0, v3, v2}, Llb0/j0;-><init>(Llb0/k0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    invoke-static {v0, v1}, Llp/sf;->c(Lyy0/m1;Lay0/n;)Lyy0/m1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    new-instance v1, Lac/k;

    .line 19
    .line 20
    const/16 v2, 0x19

    .line 21
    .line 22
    invoke-direct {v1, v3, p0, v2}, Lac/k;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 23
    .line 24
    .line 25
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    new-instance v1, Lac/k;

    .line 30
    .line 31
    const/16 v2, 0x1a

    .line 32
    .line 33
    invoke-direct {v1, v2, p0, p1, v3}, Lac/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 34
    .line 35
    .line 36
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iget-object v0, p0, Llb0/k0;->c:Lsf0/a;

    .line 41
    .line 42
    invoke-static {p1, v0, v3}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    new-instance v0, Llb0/j0;

    .line 47
    .line 48
    const/4 v1, 0x1

    .line 49
    invoke-direct {v0, p0, v3, v1}, Llb0/j0;-><init>(Llb0/k0;Lkotlin/coroutines/Continuation;I)V

    .line 50
    .line 51
    .line 52
    invoke-static {v0, p1}, Llp/ae;->c(Lay0/n;Lyy0/i;)Lyy0/m1;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Llb0/h0;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Llb0/k0;->b(Llb0/h0;)Lyy0/m1;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
