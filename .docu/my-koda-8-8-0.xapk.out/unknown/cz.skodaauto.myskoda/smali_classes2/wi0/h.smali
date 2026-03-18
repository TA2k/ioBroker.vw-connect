.class public final Lwi0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lui0/g;


# direct methods
.method public constructor <init>(Lui0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwi0/h;->a:Lui0/g;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lwi0/h;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lwi0/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lwi0/g;

    .line 7
    .line 8
    iget v1, v0, Lwi0/g;->f:I

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
    iput v1, v0, Lwi0/g;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwi0/g;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lwi0/g;-><init>(Lwi0/h;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lwi0/g;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwi0/g;->f:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v4, :cond_1

    .line 36
    .line 37
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    iput v4, v0, Lwi0/g;->f:I

    .line 53
    .line 54
    iget-object p0, p0, Lwi0/h;->a:Lui0/g;

    .line 55
    .line 56
    iget-object p1, p0, Lui0/g;->a:Lxl0/f;

    .line 57
    .line 58
    new-instance v2, La90/s;

    .line 59
    .line 60
    const/16 v5, 0x1c

    .line 61
    .line 62
    invoke-direct {v2, p0, v3, v5}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 63
    .line 64
    .line 65
    new-instance p0, Lu2/d;

    .line 66
    .line 67
    const/16 v5, 0xf

    .line 68
    .line 69
    invoke-direct {p0, v5}, Lu2/d;-><init>(I)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {p1, v2, p0, v3, v0}, Lxl0/f;->g(Lay0/k;Lay0/k;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    if-ne p1, v1, :cond_3

    .line 77
    .line 78
    return-object v1

    .line 79
    :cond_3
    :goto_1
    check-cast p1, Lne0/t;

    .line 80
    .line 81
    instance-of p0, p1, Lne0/e;

    .line 82
    .line 83
    if-eqz p0, :cond_4

    .line 84
    .line 85
    move-object v3, p1

    .line 86
    check-cast v3, Lne0/e;

    .line 87
    .line 88
    :cond_4
    const/4 p0, 0x0

    .line 89
    if-eqz v3, :cond_5

    .line 90
    .line 91
    iget-object p1, v3, Lne0/e;->a:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast p1, Lyi0/f;

    .line 94
    .line 95
    if-eqz p1, :cond_5

    .line 96
    .line 97
    iget-boolean p1, p1, Lyi0/f;->a:Z

    .line 98
    .line 99
    if-nez p1, :cond_5

    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_5
    move v4, p0

    .line 103
    :goto_2
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0
.end method
