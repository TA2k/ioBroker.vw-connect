.class public final Lw70/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lu70/c;

.field public final b:Lfg0/d;


# direct methods
.method public constructor <init>(Lu70/c;Lfg0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/f;->a:Lu70/c;

    .line 5
    .line 6
    iput-object p2, p0, Lw70/f;->b:Lfg0/d;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lw70/f;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lw70/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lw70/e;

    .line 7
    .line 8
    iget v1, v0, Lw70/e;->g:I

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
    iput v1, v0, Lw70/e;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lw70/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lw70/e;-><init>(Lw70/f;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lw70/e;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lw70/e;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_3

    .line 33
    .line 34
    if-ne v2, v3, :cond_2

    .line 35
    .line 36
    iget-object p1, v0, Lw70/e;->d:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    :cond_1
    move-object v4, p1

    .line 42
    goto :goto_1

    .line 43
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    iget-object p2, p0, Lw70/f;->b:Lfg0/d;

    .line 55
    .line 56
    invoke-virtual {p2}, Lfg0/d;->invoke()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p2

    .line 60
    check-cast p2, Lyy0/i;

    .line 61
    .line 62
    iput-object p1, v0, Lw70/e;->d:Ljava/lang/String;

    .line 63
    .line 64
    iput v3, v0, Lw70/e;->g:I

    .line 65
    .line 66
    invoke-static {p2, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    if-ne p2, v1, :cond_1

    .line 71
    .line 72
    return-object v1

    .line 73
    :goto_1
    move-object v5, p2

    .line 74
    check-cast v5, Lgg0/a;

    .line 75
    .line 76
    iget-object v3, p0, Lw70/f;->a:Lu70/c;

    .line 77
    .line 78
    const-string p0, "query"

    .line 79
    .line 80
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    iget-object p0, v3, Lu70/c;->a:Lxl0/f;

    .line 84
    .line 85
    new-instance v2, Lo10/l;

    .line 86
    .line 87
    const/16 v7, 0xc

    .line 88
    .line 89
    const/4 v6, 0x0

    .line 90
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 91
    .line 92
    .line 93
    new-instance p1, Lu2/d;

    .line 94
    .line 95
    const/4 p2, 0x3

    .line 96
    invoke-direct {p1, p2}, Lu2/d;-><init>(I)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {p0, v2, p1, v6}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0
.end method
