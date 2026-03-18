.class public final Lkc0/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lbd0/a;

.field public final b:Lkc0/f;


# direct methods
.method public constructor <init>(Lbd0/a;Lkc0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkc0/h0;->a:Lbd0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lkc0/h0;->b:Lkc0/f;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ldd0/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lkc0/h0;->b(Ldd0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ldd0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lkc0/g0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lkc0/g0;

    .line 7
    .line 8
    iget v1, v0, Lkc0/g0;->g:I

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
    iput v1, v0, Lkc0/g0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lkc0/g0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lkc0/g0;-><init>(Lkc0/h0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lkc0/g0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lkc0/g0;->g:I

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
    iget-object p1, v0, Lkc0/g0;->d:Ldd0/a;

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
    iput-object p1, v0, Lkc0/g0;->d:Ldd0/a;

    .line 54
    .line 55
    iput v3, v0, Lkc0/g0;->g:I

    .line 56
    .line 57
    iget-object p2, p0, Lkc0/h0;->b:Lkc0/f;

    .line 58
    .line 59
    invoke-virtual {p2, v0}, Lkc0/f;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    if-ne p2, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    :goto_1
    new-instance v1, Ljava/net/URL;

    .line 67
    .line 68
    iget-object p2, p1, Ldd0/a;->a:Ljava/lang/String;

    .line 69
    .line 70
    invoke-direct {v1, p2}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    iget-boolean v2, p1, Ldd0/a;->b:Z

    .line 74
    .line 75
    iget-boolean v3, p1, Ldd0/a;->c:Z

    .line 76
    .line 77
    iget-boolean v4, p1, Ldd0/a;->d:Z

    .line 78
    .line 79
    iget-boolean v5, p1, Ldd0/a;->e:Z

    .line 80
    .line 81
    iget-object p0, p0, Lkc0/h0;->a:Lbd0/a;

    .line 82
    .line 83
    move-object v0, p0

    .line 84
    check-cast v0, Lzc0/b;

    .line 85
    .line 86
    invoke-virtual/range {v0 .. v5}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0
.end method
