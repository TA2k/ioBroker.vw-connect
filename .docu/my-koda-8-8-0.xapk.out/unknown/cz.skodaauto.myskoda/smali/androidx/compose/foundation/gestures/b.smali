.class public abstract Landroidx/compose/foundation/gestures/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lfw0/i0;

.field public static final b:Lg1/h2;

.field public static final c:Lg1/g2;

.field public static final d:Lg1/i2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lfw0/i0;

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lfw0/i0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Landroidx/compose/foundation/gestures/b;->a:Lfw0/i0;

    .line 9
    .line 10
    new-instance v0, Lg1/h2;

    .line 11
    .line 12
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    sput-object v0, Landroidx/compose/foundation/gestures/b;->b:Lg1/h2;

    .line 16
    .line 17
    new-instance v0, Lg1/g2;

    .line 18
    .line 19
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 20
    .line 21
    .line 22
    sput-object v0, Landroidx/compose/foundation/gestures/b;->c:Lg1/g2;

    .line 23
    .line 24
    new-instance v0, Lg1/i2;

    .line 25
    .line 26
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    sput-object v0, Landroidx/compose/foundation/gestures/b;->d:Lg1/i2;

    .line 30
    .line 31
    return-void
.end method

.method public static final a(Lg1/u2;JLrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p3, Lg1/j2;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lg1/j2;

    .line 7
    .line 8
    iget v1, v0, Lg1/j2;->g:I

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
    iput v1, v0, Lg1/j2;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/j2;

    .line 21
    .line 22
    invoke-direct {v0, p3}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lg1/j2;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/j2;->g:I

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
    iget-object p0, v0, Lg1/j2;->e:Lkotlin/jvm/internal/c0;

    .line 37
    .line 38
    iget-object p1, v0, Lg1/j2;->d:Lg1/u2;

    .line 39
    .line 40
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    move-object v8, p0

    .line 44
    move-object p0, p1

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
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    new-instance v8, Lkotlin/jvm/internal/c0;

    .line 58
    .line 59
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 60
    .line 61
    .line 62
    sget-object p3, Le1/w0;->d:Le1/w0;

    .line 63
    .line 64
    new-instance v4, Le1/b;

    .line 65
    .line 66
    const/4 v9, 0x0

    .line 67
    const/4 v10, 0x3

    .line 68
    move-object v5, p0

    .line 69
    move-wide v6, p1

    .line 70
    invoke-direct/range {v4 .. v10}, Le1/b;-><init>(Ljava/lang/Object;JLjava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 71
    .line 72
    .line 73
    iput-object v5, v0, Lg1/j2;->d:Lg1/u2;

    .line 74
    .line 75
    iput-object v8, v0, Lg1/j2;->e:Lkotlin/jvm/internal/c0;

    .line 76
    .line 77
    iput v3, v0, Lg1/j2;->g:I

    .line 78
    .line 79
    invoke-virtual {v5, p3, v4, v0}, Lg1/u2;->f(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    if-ne p0, v1, :cond_3

    .line 84
    .line 85
    return-object v1

    .line 86
    :cond_3
    move-object p0, v5

    .line 87
    :goto_1
    iget p1, v8, Lkotlin/jvm/internal/c0;->d:F

    .line 88
    .line 89
    invoke-virtual {p0, p1}, Lg1/u2;->h(F)J

    .line 90
    .line 91
    .line 92
    move-result-wide p0

    .line 93
    new-instance p2, Ld3/b;

    .line 94
    .line 95
    invoke-direct {p2, p0, p1}, Ld3/b;-><init>(J)V

    .line 96
    .line 97
    .line 98
    return-object p2
.end method

.method public static b(Lx2/s;Lg1/q2;Lg1/w1;ZZLi1/l;I)Lx2/s;
    .locals 6

    .line 1
    and-int/lit8 p6, p6, 0x20

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    const/4 p5, 0x0

    .line 6
    :cond_0
    move-object v5, p5

    .line 7
    new-instance v0, Landroidx/compose/foundation/gestures/ScrollableElement;

    .line 8
    .line 9
    move-object v1, p1

    .line 10
    move-object v2, p2

    .line 11
    move v3, p3

    .line 12
    move v4, p4

    .line 13
    invoke-direct/range {v0 .. v5}, Landroidx/compose/foundation/gestures/ScrollableElement;-><init>(Lg1/q2;Lg1/w1;ZZLi1/l;)V

    .line 14
    .line 15
    .line 16
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
