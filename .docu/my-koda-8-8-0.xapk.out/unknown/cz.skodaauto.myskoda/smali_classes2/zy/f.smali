.class public final Lzy/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lxy/e;


# direct methods
.method public constructor <init>(Lxy/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzy/f;->a:Lxy/e;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lzy/d;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lzy/f;->b(Lzy/d;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lzy/d;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lzy/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lzy/e;

    .line 7
    .line 8
    iget v1, v0, Lzy/e;->f:I

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
    iput v1, v0, Lzy/e;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lzy/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lzy/e;-><init>(Lzy/f;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lzy/e;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lzy/e;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v4, :cond_1

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    return-object v3

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
    iget-object p2, p1, Lzy/d;->a:Laz/h;

    .line 54
    .line 55
    iget v2, p1, Lzy/d;->b:I

    .line 56
    .line 57
    iget-boolean v5, p1, Lzy/d;->c:Z

    .line 58
    .line 59
    iget-boolean p1, p1, Lzy/d;->d:Z

    .line 60
    .line 61
    iput v4, v0, Lzy/e;->f:I

    .line 62
    .line 63
    iget-object p0, p0, Lzy/f;->a:Lxy/e;

    .line 64
    .line 65
    iput-object p2, p0, Lxy/e;->f:Laz/h;

    .line 66
    .line 67
    iput-boolean p1, p0, Lxy/e;->i:Z

    .line 68
    .line 69
    iput v2, p0, Lxy/e;->h:I

    .line 70
    .line 71
    iput-boolean v5, p0, Lxy/e;->g:Z

    .line 72
    .line 73
    if-ne v3, v1, :cond_3

    .line 74
    .line 75
    return-object v1

    .line 76
    :cond_3
    return-object v3
.end method
