.class public abstract Lf2/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lc1/a2;

.field public static final b:Lc1/a2;

.field public static final c:Lc1/a2;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Lc1/a2;

    .line 2
    .line 3
    sget-object v1, Lc1/z;->a:Lc1/s;

    .line 4
    .line 5
    const/16 v2, 0x78

    .line 6
    .line 7
    const/4 v3, 0x2

    .line 8
    invoke-direct {v0, v2, v1, v3}, Lc1/a2;-><init>(ILc1/w;I)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lf2/x;->a:Lc1/a2;

    .line 12
    .line 13
    new-instance v0, Lc1/a2;

    .line 14
    .line 15
    new-instance v1, Lc1/s;

    .line 16
    .line 17
    const v4, 0x3ecccccd    # 0.4f

    .line 18
    .line 19
    .line 20
    const/4 v5, 0x0

    .line 21
    const v6, 0x3f19999a    # 0.6f

    .line 22
    .line 23
    .line 24
    const/high16 v7, 0x3f800000    # 1.0f

    .line 25
    .line 26
    invoke-direct {v1, v4, v5, v6, v7}, Lc1/s;-><init>(FFFF)V

    .line 27
    .line 28
    .line 29
    const/16 v8, 0x96

    .line 30
    .line 31
    invoke-direct {v0, v8, v1, v3}, Lc1/a2;-><init>(ILc1/w;I)V

    .line 32
    .line 33
    .line 34
    sput-object v0, Lf2/x;->b:Lc1/a2;

    .line 35
    .line 36
    new-instance v0, Lc1/a2;

    .line 37
    .line 38
    new-instance v1, Lc1/s;

    .line 39
    .line 40
    invoke-direct {v1, v4, v5, v6, v7}, Lc1/s;-><init>(FFFF)V

    .line 41
    .line 42
    .line 43
    invoke-direct {v0, v2, v1, v3}, Lc1/a2;-><init>(ILc1/w;I)V

    .line 44
    .line 45
    .line 46
    sput-object v0, Lf2/x;->c:Lc1/a2;

    .line 47
    .line 48
    return-void
.end method

.method public static final a(Lc1/c;FLi1/k;Li1/k;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p3, :cond_4

    .line 3
    .line 4
    instance-of p2, p3, Li1/n;

    .line 5
    .line 6
    sget-object v1, Lf2/x;->a:Lc1/a2;

    .line 7
    .line 8
    if-eqz p2, :cond_0

    .line 9
    .line 10
    :goto_0
    move-object v0, v1

    .line 11
    goto :goto_1

    .line 12
    :cond_0
    instance-of p2, p3, Li1/b;

    .line 13
    .line 14
    if-eqz p2, :cond_1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    instance-of p2, p3, Li1/i;

    .line 18
    .line 19
    if-eqz p2, :cond_2

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_2
    instance-of p2, p3, Li1/e;

    .line 23
    .line 24
    if-eqz p2, :cond_3

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_3
    :goto_1
    move-object v3, v0

    .line 28
    goto :goto_3

    .line 29
    :cond_4
    if-eqz p2, :cond_3

    .line 30
    .line 31
    instance-of p3, p2, Li1/n;

    .line 32
    .line 33
    sget-object v1, Lf2/x;->b:Lc1/a2;

    .line 34
    .line 35
    if-eqz p3, :cond_5

    .line 36
    .line 37
    :goto_2
    goto :goto_0

    .line 38
    :cond_5
    instance-of p3, p2, Li1/b;

    .line 39
    .line 40
    if-eqz p3, :cond_6

    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_6
    instance-of p3, p2, Li1/i;

    .line 44
    .line 45
    if-eqz p3, :cond_7

    .line 46
    .line 47
    sget-object v0, Lf2/x;->c:Lc1/a2;

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_7
    instance-of p2, p2, Li1/e;

    .line 51
    .line 52
    if-eqz p2, :cond_3

    .line 53
    .line 54
    goto :goto_2

    .line 55
    :goto_3
    if-eqz v3, :cond_8

    .line 56
    .line 57
    new-instance v2, Lt4/f;

    .line 58
    .line 59
    invoke-direct {v2, p1}, Lt4/f;-><init>(F)V

    .line 60
    .line 61
    .line 62
    const/4 v5, 0x0

    .line 63
    const/16 v7, 0xc

    .line 64
    .line 65
    const/4 v4, 0x0

    .line 66
    move-object v1, p0

    .line 67
    move-object v6, p4

    .line 68
    invoke-static/range {v1 .. v7}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 73
    .line 74
    if-ne p0, p1, :cond_9

    .line 75
    .line 76
    return-object p0

    .line 77
    :cond_8
    move-object v1, p0

    .line 78
    move-object v6, p4

    .line 79
    new-instance p0, Lt4/f;

    .line 80
    .line 81
    invoke-direct {p0, p1}, Lt4/f;-><init>(F)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v1, p0, v6}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 89
    .line 90
    if-ne p0, p1, :cond_9

    .line 91
    .line 92
    return-object p0

    .line 93
    :cond_9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 94
    .line 95
    return-object p0
.end method
