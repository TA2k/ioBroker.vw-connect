.class public final Ll00/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Ll00/f;

.field public final b:Lkf0/o;


# direct methods
.method public constructor <init>(Ll00/f;Lkf0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll00/n;->a:Ll00/f;

    .line 5
    .line 6
    iput-object p2, p0, Ll00/n;->b:Lkf0/o;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Ll00/n;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Ll00/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ll00/m;

    .line 7
    .line 8
    iget v1, v0, Ll00/m;->f:I

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
    iput v1, v0, Ll00/m;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ll00/m;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ll00/m;-><init>(Ll00/n;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ll00/m;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ll00/m;->f:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v4, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object v5

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput v4, v0, Ll00/m;->f:I

    .line 61
    .line 62
    iget-object p1, p0, Ll00/n;->b:Lkf0/o;

    .line 63
    .line 64
    invoke-virtual {p1, v0}, Lkf0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    if-ne p1, v1, :cond_4

    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_4
    :goto_1
    instance-of v2, p1, Lne0/e;

    .line 72
    .line 73
    const/4 v4, 0x0

    .line 74
    if-eqz v2, :cond_5

    .line 75
    .line 76
    check-cast p1, Lne0/e;

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_5
    move-object p1, v4

    .line 80
    :goto_2
    if-eqz p1, :cond_7

    .line 81
    .line 82
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast p1, Lss0/j0;

    .line 85
    .line 86
    iget-object p1, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 87
    .line 88
    iput v3, v0, Ll00/m;->f:I

    .line 89
    .line 90
    iget-object p0, p0, Ll00/n;->a:Ll00/f;

    .line 91
    .line 92
    check-cast p0, Lj00/i;

    .line 93
    .line 94
    iget-object p0, p0, Lj00/i;->b:Ljava/util/LinkedHashSet;

    .line 95
    .line 96
    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    if-ne v5, v1, :cond_6

    .line 100
    .line 101
    :goto_3
    return-object v1

    .line 102
    :cond_6
    return-object v5

    .line 103
    :cond_7
    return-object v4
.end method
