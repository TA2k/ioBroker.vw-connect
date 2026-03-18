.class public final Lsg/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljd/b;

.field public final b:Lxh/e;

.field public final c:Ljava/lang/String;

.field public d:Ljava/util/List;

.field public e:Lnc/z;

.field public f:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljd/b;Lxh/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lsg/e;->a:Ljd/b;

    .line 5
    .line 6
    iput-object p3, p0, Lsg/e;->b:Lxh/e;

    .line 7
    .line 8
    iput-object p1, p0, Lsg/e;->c:Ljava/lang/String;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lsg/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lsg/d;

    .line 7
    .line 8
    iget v1, v0, Lsg/d;->f:I

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
    iput v1, v0, Lsg/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lsg/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lsg/d;-><init>(Lsg/e;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lsg/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lsg/d;->f:I

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
    iput v3, v0, Lsg/d;->f:I

    .line 52
    .line 53
    iget-object p1, p0, Lsg/e;->a:Ljd/b;

    .line 54
    .line 55
    iget-object v2, p0, Lsg/e;->c:Ljava/lang/String;

    .line 56
    .line 57
    invoke-virtual {p1, v2, v0}, Ljd/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    if-ne p1, v1, :cond_3

    .line 62
    .line 63
    return-object v1

    .line 64
    :cond_3
    :goto_1
    check-cast p1, Llx0/o;

    .line 65
    .line 66
    iget-object p1, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 67
    .line 68
    instance-of v0, p1, Llx0/n;

    .line 69
    .line 70
    if-nez v0, :cond_4

    .line 71
    .line 72
    :try_start_0
    check-cast p1, Lkg/g0;

    .line 73
    .line 74
    iget-object v0, p1, Lkg/g0;->b:Ljava/util/List;

    .line 75
    .line 76
    iput-object v0, p0, Lsg/e;->d:Ljava/util/List;

    .line 77
    .line 78
    iget-object v0, p1, Lkg/g0;->c:Lnc/z;

    .line 79
    .line 80
    iput-object v0, p0, Lsg/e;->e:Lnc/z;

    .line 81
    .line 82
    iget-object v0, p1, Lkg/g0;->d:Ljava/lang/String;

    .line 83
    .line 84
    iput-object v0, p0, Lsg/e;->f:Ljava/lang/String;

    .line 85
    .line 86
    iget-object p0, p1, Lkg/g0;->a:Ljava/util/List;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 87
    .line 88
    return-object p0

    .line 89
    :catchall_0
    move-exception p0

    .line 90
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    return-object p0

    .line 95
    :cond_4
    return-object p1
.end method
