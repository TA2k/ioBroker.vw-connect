.class public abstract Ld71/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/e0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lc91/u;

    .line 2
    .line 3
    const/16 v1, 0x1d

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lc91/u;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/e0;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Ld71/e;->a:Ll2/e0;

    .line 14
    .line 15
    return-void
.end method

.method public static final a(Lt2/b;Ll2/o;I)V
    .locals 3

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, 0x68126bd7

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
    if-eqz v0, :cond_2

    .line 24
    .line 25
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 30
    .line 31
    if-ne v0, v1, :cond_1

    .line 32
    .line 33
    new-instance v0, Ld71/c;

    .line 34
    .line 35
    invoke-direct {v0}, Ld71/c;-><init>()V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p1, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    :cond_1
    check-cast v0, Ld71/c;

    .line 42
    .line 43
    sget-object v1, Ld71/e;->a:Ll2/e0;

    .line 44
    .line 45
    invoke-virtual {v1, v0}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    new-instance v1, Ld71/d;

    .line 50
    .line 51
    const/4 v2, 0x0

    .line 52
    invoke-direct {v1, p0, v2}, Ld71/d;-><init>(Lt2/b;I)V

    .line 53
    .line 54
    .line 55
    const v2, 0x57e57097

    .line 56
    .line 57
    .line 58
    invoke-static {v2, p1, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    const/16 v2, 0x38

    .line 63
    .line 64
    invoke-static {v0, v1, p1, v2}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 65
    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 69
    .line 70
    .line 71
    :goto_1
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    if-eqz p1, :cond_3

    .line 76
    .line 77
    new-instance v0, Ld71/d;

    .line 78
    .line 79
    const/4 v1, 0x1

    .line 80
    invoke-direct {v0, p0, p2, v1}, Ld71/d;-><init>(Lt2/b;II)V

    .line 81
    .line 82
    .line 83
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 84
    .line 85
    :cond_3
    return-void
.end method
