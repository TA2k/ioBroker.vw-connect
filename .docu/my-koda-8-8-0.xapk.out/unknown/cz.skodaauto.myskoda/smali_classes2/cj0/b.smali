.class public final Lcj0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lfj0/f;


# instance fields
.field public final a:Lve0/u;


# direct methods
.method public constructor <init>(Lve0/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcj0/b;->a:Lve0/u;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lcj0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lcj0/a;

    .line 7
    .line 8
    iget v1, v0, Lcj0/a;->g:I

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
    iput v1, v0, Lcj0/a;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcj0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lcj0/a;-><init>(Lcj0/b;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lcj0/a;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcj0/a;->g:I

    .line 30
    .line 31
    const-string v3, "PREF_STORED_LANGUAGE"

    .line 32
    .line 33
    iget-object p0, p0, Lcj0/b;->a:Lve0/u;

    .line 34
    .line 35
    const/4 v4, 0x2

    .line 36
    const/4 v5, 0x1

    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    if-eq v2, v5, :cond_2

    .line 40
    .line 41
    if-ne v2, v4, :cond_1

    .line 42
    .line 43
    iget-object p0, v0, Lcj0/a;->d:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return-object p0

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iput v5, v0, Lcj0/a;->g:I

    .line 65
    .line 66
    invoke-virtual {p0, v3, v0}, Lve0/u;->f(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    if-ne p1, v1, :cond_4

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    :goto_1
    check-cast p1, Ljava/lang/String;

    .line 74
    .line 75
    iput-object p1, v0, Lcj0/a;->d:Ljava/lang/String;

    .line 76
    .line 77
    iput v4, v0, Lcj0/a;->g:I

    .line 78
    .line 79
    invoke-virtual {p0, v3, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    if-ne p0, v1, :cond_5

    .line 84
    .line 85
    :goto_2
    return-object v1

    .line 86
    :cond_5
    return-object p1
.end method
