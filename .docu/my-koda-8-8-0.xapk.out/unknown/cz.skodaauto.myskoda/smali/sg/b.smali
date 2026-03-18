.class public final Lsg/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljd/b;

.field public final c:Lxh/e;

.field public d:Ljava/util/List;

.field public e:Z

.field public f:Ljava/util/List;

.field public g:Lac/a0;

.field public h:Lnc/z;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljd/b;Lxh/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lsg/b;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lsg/b;->b:Ljd/b;

    .line 7
    .line 8
    iput-object p3, p0, Lsg/b;->c:Lxh/e;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lsg/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lsg/a;

    .line 7
    .line 8
    iget v1, v0, Lsg/a;->f:I

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
    iput v1, v0, Lsg/a;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lsg/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lsg/a;-><init>(Lsg/b;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lsg/a;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lsg/a;->f:I

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
    iput v3, v0, Lsg/a;->f:I

    .line 52
    .line 53
    iget-object p1, p0, Lsg/b;->b:Ljd/b;

    .line 54
    .line 55
    iget-object v2, p0, Lsg/b;->a:Ljava/lang/String;

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
    check-cast p1, Lkg/a0;

    .line 73
    .line 74
    iget-object v0, p1, Lkg/a0;->b:Ljava/util/List;

    .line 75
    .line 76
    iput-object v0, p0, Lsg/b;->d:Ljava/util/List;

    .line 77
    .line 78
    iget-boolean v0, p1, Lkg/a0;->c:Z

    .line 79
    .line 80
    iput-boolean v0, p0, Lsg/b;->e:Z

    .line 81
    .line 82
    iget-object v0, p1, Lkg/a0;->a:Ljava/util/List;

    .line 83
    .line 84
    iput-object v0, p0, Lsg/b;->f:Ljava/util/List;

    .line 85
    .line 86
    iget-object v0, p1, Lkg/a0;->d:Lac/a0;

    .line 87
    .line 88
    iput-object v0, p0, Lsg/b;->g:Lac/a0;

    .line 89
    .line 90
    iget-object v0, p1, Lkg/a0;->f:Lnc/z;

    .line 91
    .line 92
    iput-object v0, p0, Lsg/b;->h:Lnc/z;

    .line 93
    .line 94
    iget-object p0, p1, Lkg/a0;->e:Ljava/util/List;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 95
    .line 96
    return-object p0

    .line 97
    :catchall_0
    move-exception p0

    .line 98
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    return-object p0

    .line 103
    :cond_4
    return-object p1
.end method
