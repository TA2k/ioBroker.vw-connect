.class public abstract Li71/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh71/p;

.field public static final b:Lh71/r;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lh71/p;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Li71/c;->a:Lh71/p;

    .line 7
    .line 8
    new-instance v0, Lh71/r;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Li71/c;->b:Lh71/r;

    .line 14
    .line 15
    return-void
.end method

.method public static final a(Lt2/b;Ll2/o;I)V
    .locals 6

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, 0x64e37370

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p2, 0x3

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    if-eq v0, v1, :cond_0

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 v0, 0x0

    .line 17
    :goto_0
    and-int/lit8 v1, p2, 0x1

    .line 18
    .line 19
    invoke-virtual {p1, v1, v0}, Ll2/t;->O(IZ)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    sget-object v0, Li71/b;->a:Lh71/n;

    .line 26
    .line 27
    sget-object v1, Li71/d;->a:Lh71/t;

    .line 28
    .line 29
    sput-object v0, Llp/q0;->a:Lh71/n;

    .line 30
    .line 31
    sput-object v1, Llp/q0;->b:Lh71/t;

    .line 32
    .line 33
    sget-object v2, Lh71/m;->a:Ll2/u2;

    .line 34
    .line 35
    sget-object v3, Li71/a;->a:Lh71/l;

    .line 36
    .line 37
    invoke-virtual {v2, v3}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    sget-object v3, Lh71/o;->a:Ll2/u2;

    .line 42
    .line 43
    invoke-virtual {v3, v0}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sget-object v3, Lh71/q;->a:Ll2/e0;

    .line 48
    .line 49
    sget-object v4, Li71/c;->a:Lh71/p;

    .line 50
    .line 51
    invoke-virtual {v3, v4}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    sget-object v4, Lh71/s;->a:Ll2/e0;

    .line 56
    .line 57
    sget-object v5, Li71/c;->b:Lh71/r;

    .line 58
    .line 59
    invoke-virtual {v4, v5}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    sget-object v5, Lh71/u;->a:Ll2/u2;

    .line 64
    .line 65
    invoke-virtual {v5, v1}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    filled-new-array {v2, v0, v3, v4, v1}, [Ll2/t1;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    new-instance v1, Ld71/d;

    .line 74
    .line 75
    const/4 v2, 0x7

    .line 76
    invoke-direct {v1, p0, v2}, Ld71/d;-><init>(Lt2/b;I)V

    .line 77
    .line 78
    .line 79
    const v2, 0x6bf97830

    .line 80
    .line 81
    .line 82
    invoke-static {v2, p1, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    const/16 v2, 0x38

    .line 87
    .line 88
    invoke-static {v0, v1, p1, v2}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 89
    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 93
    .line 94
    .line 95
    :goto_1
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    if-eqz p1, :cond_2

    .line 100
    .line 101
    new-instance v0, Ld71/d;

    .line 102
    .line 103
    const/16 v1, 0x8

    .line 104
    .line 105
    invoke-direct {v0, p0, p2, v1}, Ld71/d;-><init>(Lt2/b;II)V

    .line 106
    .line 107
    .line 108
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 109
    .line 110
    :cond_2
    return-void
.end method
