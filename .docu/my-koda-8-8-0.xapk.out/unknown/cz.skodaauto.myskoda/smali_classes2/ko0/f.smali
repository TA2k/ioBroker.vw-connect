.class public final Lko0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Ljn0/c;


# direct methods
.method public constructor <init>(Ljn0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lko0/f;->a:Ljn0/c;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lne0/c;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lko0/f;->b(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p2, Lko0/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lko0/e;

    .line 7
    .line 8
    iget v1, v0, Lko0/e;->f:I

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
    iput v1, v0, Lko0/e;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lko0/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lko0/e;-><init>(Lko0/f;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lko0/e;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lko0/e;->f:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    new-instance v4, Lkn0/e;

    .line 52
    .line 53
    const v7, 0x7f12038c

    .line 54
    .line 55
    .line 56
    const/4 v8, 0x1

    .line 57
    const v5, 0x7f120791

    .line 58
    .line 59
    .line 60
    const v6, 0x7f12078f

    .line 61
    .line 62
    .line 63
    move-object v9, p1

    .line 64
    invoke-direct/range {v4 .. v9}, Lkn0/e;-><init>(IIIZLne0/c;)V

    .line 65
    .line 66
    .line 67
    iput v3, v0, Lko0/e;->f:I

    .line 68
    .line 69
    iget-object p0, p0, Lko0/f;->a:Ljn0/c;

    .line 70
    .line 71
    invoke-virtual {p0, v4, v0}, Ljn0/c;->b(Lkn0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    if-ne p0, v1, :cond_3

    .line 76
    .line 77
    return-object v1

    .line 78
    :cond_3
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 79
    .line 80
    return-object p0
.end method
