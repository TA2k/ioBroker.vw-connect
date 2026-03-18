.class public final Lk90/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lgf0/f;


# direct methods
.method public constructor <init>(Lgf0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk90/p;->a:Lgf0/f;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/util/Map;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lk90/p;->b(Ljava/util/Map;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ljava/util/Map;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of p1, p2, Lk90/o;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    move-object p1, p2

    .line 6
    check-cast p1, Lk90/o;

    .line 7
    .line 8
    iget v0, p1, Lk90/o;->f:I

    .line 9
    .line 10
    const/high16 v1, -0x80000000

    .line 11
    .line 12
    and-int v2, v0, v1

    .line 13
    .line 14
    if-eqz v2, :cond_0

    .line 15
    .line 16
    sub-int/2addr v0, v1

    .line 17
    iput v0, p1, Lk90/o;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance p1, Lk90/o;

    .line 21
    .line 22
    invoke-direct {p1, p0, p2}, Lk90/o;-><init>(Lk90/p;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, p1, Lk90/o;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, p1, Lk90/o;->f:I

    .line 30
    .line 31
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v3, 0x1

    .line 34
    if-eqz v1, :cond_2

    .line 35
    .line 36
    if-ne v1, v3, :cond_1

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
    new-instance p2, Lhf0/c;

    .line 54
    .line 55
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 56
    .line 57
    .line 58
    iput v3, p1, Lk90/o;->f:I

    .line 59
    .line 60
    iget-object p0, p0, Lk90/p;->a:Lgf0/f;

    .line 61
    .line 62
    iget-object p0, p0, Lgf0/f;->a:Lgf0/b;

    .line 63
    .line 64
    check-cast p0, Ldf0/a;

    .line 65
    .line 66
    iget-object p0, p0, Ldf0/a;->a:Lyy0/c2;

    .line 67
    .line 68
    invoke-virtual {p0, p2}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    if-ne v2, v0, :cond_3

    .line 72
    .line 73
    return-object v0

    .line 74
    :cond_3
    :goto_1
    new-instance p0, Lne0/e;

    .line 75
    .line 76
    invoke-direct {p0, v2}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    return-object p0
.end method
