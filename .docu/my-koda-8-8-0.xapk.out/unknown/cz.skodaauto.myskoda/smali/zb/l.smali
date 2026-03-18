.class public abstract Lzb/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/u2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lz81/g;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Lz81/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Ll2/u2;

    .line 8
    .line 9
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 10
    .line 11
    .line 12
    sput-object v1, Lzb/l;->a:Ll2/u2;

    .line 13
    .line 14
    return-void
.end method

.method public static final a(Lt2/b;Ll2/o;I)V
    .locals 3

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, 0x786ab707

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
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 34
    .line 35
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-virtual {p1, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    :cond_1
    check-cast v0, Ll2/b1;

    .line 43
    .line 44
    sget-object v1, Lzb/l;->a:Ll2/u2;

    .line 45
    .line 46
    invoke-virtual {v1, v0}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    new-instance v1, Ld71/d;

    .line 51
    .line 52
    const/16 v2, 0x1b

    .line 53
    .line 54
    invoke-direct {v1, p0, v2}, Ld71/d;-><init>(Lt2/b;I)V

    .line 55
    .line 56
    .line 57
    const v2, -0x75e655b9

    .line 58
    .line 59
    .line 60
    invoke-static {v2, p1, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    const/16 v2, 0x38

    .line 65
    .line 66
    invoke-static {v0, v1, p1, v2}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 71
    .line 72
    .line 73
    :goto_1
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    if-eqz p1, :cond_3

    .line 78
    .line 79
    new-instance v0, Ld71/d;

    .line 80
    .line 81
    const/16 v1, 0x1c

    .line 82
    .line 83
    invoke-direct {v0, p0, p2, v1}, Ld71/d;-><init>(Lt2/b;II)V

    .line 84
    .line 85
    .line 86
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 87
    .line 88
    :cond_3
    return-void
.end method

.method public static final b(Ll2/o;)Z
    .locals 1

    .line 1
    sget-object v0, Lzb/l;->a:Ll2/u2;

    .line 2
    .line 3
    check-cast p0, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Ll2/b1;

    .line 10
    .line 11
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Ljava/lang/Boolean;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method
