.class public final Lq10/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/m;

.field public final b:Lq10/i;

.field public final c:Lq10/c;


# direct methods
.method public constructor <init>(Lkf0/m;Lq10/i;Lq10/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq10/q;->a:Lkf0/m;

    .line 5
    .line 6
    iput-object p2, p0, Lq10/q;->b:Lq10/i;

    .line 7
    .line 8
    iput-object p3, p0, Lq10/q;->c:Lq10/c;

    .line 9
    .line 10
    return-void
.end method

.method public static final a(Lq10/q;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lq10/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lq10/o;

    .line 7
    .line 8
    iget v1, v0, Lq10/o;->f:I

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
    iput v1, v0, Lq10/o;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lq10/o;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lq10/o;-><init>(Lq10/q;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lq10/o;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lq10/o;->f:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Lq10/q;->a:Lkf0/m;

    .line 52
    .line 53
    iput v3, v0, Lq10/o;->f:I

    .line 54
    .line 55
    invoke-virtual {p0, v0}, Lkf0/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    if-ne p1, v1, :cond_3

    .line 60
    .line 61
    return-object v1

    .line 62
    :cond_3
    :goto_1
    instance-of p0, p1, Lne0/e;

    .line 63
    .line 64
    if-eqz p0, :cond_4

    .line 65
    .line 66
    check-cast p1, Lne0/e;

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_4
    const/4 p1, 0x0

    .line 70
    :goto_2
    if-eqz p1, :cond_7

    .line 71
    .line 72
    iget-object p0, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast p0, Lss0/k;

    .line 75
    .line 76
    if-nez p0, :cond_5

    .line 77
    .line 78
    goto :goto_4

    .line 79
    :cond_5
    iget-object p1, p0, Lss0/k;->j:Lss0/n;

    .line 80
    .line 81
    sget-object v0, Lss0/n;->d:Lss0/n;

    .line 82
    .line 83
    const/4 v1, 0x0

    .line 84
    if-ne p1, v0, :cond_6

    .line 85
    .line 86
    iget-object p0, p0, Lss0/k;->f:Ljava/lang/String;

    .line 87
    .line 88
    const-string p1, "NE"

    .line 89
    .line 90
    invoke-static {p0, p1, v1}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 91
    .line 92
    .line 93
    move-result p0

    .line 94
    if-eqz p0, :cond_6

    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_6
    move v3, v1

    .line 98
    :goto_3
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    return-object p0

    .line 103
    :cond_7
    :goto_4
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 104
    .line 105
    return-object p0
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lq10/q;->b:Lq10/i;

    .line 2
    .line 3
    sget-object v1, Lr10/c;->e:Lr10/c;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lq10/i;->a(Lr10/c;)Lac/l;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    new-instance v1, Lrz/k;

    .line 10
    .line 11
    const/16 v2, 0x15

    .line 12
    .line 13
    invoke-direct {v1, v0, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 14
    .line 15
    .line 16
    new-instance v0, Lmc/e;

    .line 17
    .line 18
    const/16 v2, 0x17

    .line 19
    .line 20
    invoke-direct {v0, p0, v2}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 21
    .line 22
    .line 23
    new-instance v2, Lbn0/f;

    .line 24
    .line 25
    const/4 v3, 0x3

    .line 26
    invoke-direct {v2, v1, p0, v0, v3}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 27
    .line 28
    .line 29
    return-object v2
.end method
