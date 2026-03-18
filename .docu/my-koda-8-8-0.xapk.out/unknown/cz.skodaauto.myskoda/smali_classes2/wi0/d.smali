.class public final Lwi0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lwr0/e;


# direct methods
.method public constructor <init>(Lwr0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwi0/d;->a:Lwr0/e;

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
    invoke-virtual {p0, p2}, Lwi0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lwi0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lwi0/c;

    .line 7
    .line 8
    iget v1, v0, Lwi0/c;->i:I

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
    iput v1, v0, Lwi0/c;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwi0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lwi0/c;-><init>(Lwi0/d;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lwi0/c;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwi0/c;->i:I

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
    iget-object p0, v0, Lwi0/c;->f:[Ljava/lang/Object;

    .line 37
    .line 38
    iget-object v1, v0, Lwi0/c;->e:[Ljava/lang/Object;

    .line 39
    .line 40
    iget-object v0, v0, Lwi0/c;->d:Ljava/lang/String;

    .line 41
    .line 42
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    new-array p1, v3, [Ljava/lang/Object;

    .line 58
    .line 59
    const-string v2, "https://consent.vwgroup.io/consent/v1/texts/MSP/cz/%s/TrackingPolicy/latest/html"

    .line 60
    .line 61
    iput-object v2, v0, Lwi0/c;->d:Ljava/lang/String;

    .line 62
    .line 63
    iput-object p1, v0, Lwi0/c;->e:[Ljava/lang/Object;

    .line 64
    .line 65
    iput-object p1, v0, Lwi0/c;->f:[Ljava/lang/Object;

    .line 66
    .line 67
    iput v3, v0, Lwi0/c;->i:I

    .line 68
    .line 69
    iget-object p0, p0, Lwi0/d;->a:Lwr0/e;

    .line 70
    .line 71
    iget-object p0, p0, Lwr0/e;->a:Lwr0/g;

    .line 72
    .line 73
    check-cast p0, Lur0/g;

    .line 74
    .line 75
    invoke-virtual {p0, v0}, Lur0/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    if-ne p0, v1, :cond_3

    .line 80
    .line 81
    return-object v1

    .line 82
    :cond_3
    move-object v1, p1

    .line 83
    move-object v0, v2

    .line 84
    move-object p1, p0

    .line 85
    move-object p0, v1

    .line 86
    :goto_1
    check-cast p1, Lyr0/e;

    .line 87
    .line 88
    if-eqz p1, :cond_4

    .line 89
    .line 90
    iget-object p1, p1, Lyr0/e;->h:Ljava/lang/String;

    .line 91
    .line 92
    if-nez p1, :cond_5

    .line 93
    .line 94
    :cond_4
    const-string p1, "en"

    .line 95
    .line 96
    :cond_5
    const/4 v2, 0x0

    .line 97
    aput-object p1, p0, v2

    .line 98
    .line 99
    array-length p0, v1

    .line 100
    invoke-static {v1, p0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    invoke-static {v0, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    return-object p0
.end method
