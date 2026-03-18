.class public final Lb00/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# static fields
.field public static final e:Lyy0/m;


# instance fields
.field public final a:Llb0/b;

.field public final b:Llb0/g0;

.field public final c:Lrq0/d;

.field public final d:Lko0/f;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lne0/c;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 4
    .line 5
    const-string v2, "missing target temperature"

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const/4 v4, 0x0

    .line 11
    const/16 v5, 0x1e

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 16
    .line 17
    .line 18
    new-instance v1, Lyy0/m;

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    invoke-direct {v1, v0, v2}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 22
    .line 23
    .line 24
    sput-object v1, Lb00/m;->e:Lyy0/m;

    .line 25
    .line 26
    return-void
.end method

.method public constructor <init>(Llb0/b;Llb0/g0;Lrq0/d;Lko0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lb00/m;->a:Llb0/b;

    .line 5
    .line 6
    iput-object p2, p0, Lb00/m;->b:Llb0/g0;

    .line 7
    .line 8
    iput-object p3, p0, Lb00/m;->c:Lrq0/d;

    .line 9
    .line 10
    iput-object p4, p0, Lb00/m;->d:Lko0/f;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/util/Map;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lb00/m;->b(Ljava/util/Map;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ljava/util/Map;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lb00/l;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lb00/l;

    .line 7
    .line 8
    iget v1, v0, Lb00/l;->f:I

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
    iput v1, v0, Lb00/l;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lb00/l;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lb00/l;-><init>(Lb00/m;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lb00/l;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lb00/l;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v3, :cond_1

    .line 36
    .line 37
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    new-instance p2, Llb0/a;

    .line 53
    .line 54
    const/4 v2, 0x0

    .line 55
    invoke-direct {p2, v2}, Llb0/a;-><init>(Z)V

    .line 56
    .line 57
    .line 58
    iget-object v2, p0, Lb00/m;->a:Llb0/b;

    .line 59
    .line 60
    invoke-virtual {v2, p2}, Llb0/b;->a(Llb0/a;)Lzy0/j;

    .line 61
    .line 62
    .line 63
    move-result-object p2

    .line 64
    invoke-static {p2}, Lbb/j0;->l(Lyy0/i;)Lal0/j0;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    new-instance v2, Lac/k;

    .line 69
    .line 70
    const/4 v5, 0x3

    .line 71
    invoke-direct {v2, v5, p1, p0, v4}, Lac/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 72
    .line 73
    .line 74
    invoke-static {p2, v2}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    iput v3, v0, Lb00/l;->f:I

    .line 79
    .line 80
    invoke-static {p1, v0}, Lyy0/u;->z(Lyy0/i;Lrx0/c;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p2

    .line 84
    if-ne p2, v1, :cond_3

    .line 85
    .line 86
    return-object v1

    .line 87
    :cond_3
    :goto_1
    check-cast p2, Lne0/t;

    .line 88
    .line 89
    instance-of p1, p2, Lne0/c;

    .line 90
    .line 91
    if-eqz p1, :cond_4

    .line 92
    .line 93
    move-object p1, p2

    .line 94
    check-cast p1, Lne0/c;

    .line 95
    .line 96
    sget-object v0, Lge0/a;->d:Lge0/a;

    .line 97
    .line 98
    new-instance v1, La50/c;

    .line 99
    .line 100
    const/16 v2, 0x8

    .line 101
    .line 102
    invoke-direct {v1, v2, p0, p1, v4}, La50/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 103
    .line 104
    .line 105
    const/4 p0, 0x3

    .line 106
    invoke-static {v0, v4, v4, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 107
    .line 108
    .line 109
    :cond_4
    return-object p2
.end method
