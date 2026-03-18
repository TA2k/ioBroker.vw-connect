.class public final Ll00/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/z;

.field public final b:Lwr0/e;

.field public final c:Ll00/f;

.field public final d:Ll00/l;


# direct methods
.method public constructor <init>(Lkf0/z;Lwr0/e;Ll00/f;Ll00/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll00/i;->a:Lkf0/z;

    .line 5
    .line 6
    iput-object p2, p0, Ll00/i;->b:Lwr0/e;

    .line 7
    .line 8
    iput-object p3, p0, Ll00/i;->c:Ll00/f;

    .line 9
    .line 10
    iput-object p4, p0, Ll00/i;->d:Ll00/l;

    .line 11
    .line 12
    return-void
.end method

.method public static final b(Ll00/i;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p1, Ll00/g;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p1

    .line 9
    check-cast v0, Ll00/g;

    .line 10
    .line 11
    iget v1, v0, Ll00/g;->f:I

    .line 12
    .line 13
    const/high16 v2, -0x80000000

    .line 14
    .line 15
    and-int v3, v1, v2

    .line 16
    .line 17
    if-eqz v3, :cond_0

    .line 18
    .line 19
    sub-int/2addr v1, v2

    .line 20
    iput v1, v0, Ll00/g;->f:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Ll00/g;

    .line 24
    .line 25
    invoke-direct {v0, p0, p1}, Ll00/g;-><init>(Ll00/i;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object p1, v0, Ll00/g;->d:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    iget v2, v0, Ll00/g;->f:I

    .line 33
    .line 34
    const/4 v3, 0x2

    .line 35
    const/4 v4, 0x1

    .line 36
    if-eqz v2, :cond_3

    .line 37
    .line 38
    if-eq v2, v4, :cond_2

    .line 39
    .line 40
    if-ne v2, v3, :cond_1

    .line 41
    .line 42
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    return-object p1

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
    goto :goto_1

    .line 58
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iget-object p1, p0, Ll00/i;->b:Lwr0/e;

    .line 62
    .line 63
    iput v4, v0, Ll00/g;->f:I

    .line 64
    .line 65
    iget-object p1, p1, Lwr0/e;->a:Lwr0/g;

    .line 66
    .line 67
    check-cast p1, Lur0/g;

    .line 68
    .line 69
    invoke-virtual {p1, v0}, Lur0/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    if-ne p1, v1, :cond_4

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_4
    :goto_1
    check-cast p1, Lyr0/e;

    .line 77
    .line 78
    if-eqz p1, :cond_5

    .line 79
    .line 80
    iget-object p1, p1, Lyr0/e;->f:Ljava/lang/String;

    .line 81
    .line 82
    if-nez p1, :cond_6

    .line 83
    .line 84
    :cond_5
    const/4 p1, 0x0

    .line 85
    :cond_6
    iget-object p0, p0, Ll00/i;->d:Ll00/l;

    .line 86
    .line 87
    iput v3, v0, Ll00/g;->f:I

    .line 88
    .line 89
    check-cast p0, Lj00/d;

    .line 90
    .line 91
    invoke-virtual {p0, p1, v0}, Lj00/d;->b(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    if-ne p0, v1, :cond_7

    .line 96
    .line 97
    :goto_2
    return-object v1

    .line 98
    :cond_7
    return-object p0
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Ll00/i;->a:Lkf0/z;

    .line 4
    .line 5
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Lyy0/i;

    .line 10
    .line 11
    new-instance p2, Lac/l;

    .line 12
    .line 13
    const/16 v0, 0x1c

    .line 14
    .line 15
    invoke-direct {p2, v0, p1, p0}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    return-object p2
.end method
