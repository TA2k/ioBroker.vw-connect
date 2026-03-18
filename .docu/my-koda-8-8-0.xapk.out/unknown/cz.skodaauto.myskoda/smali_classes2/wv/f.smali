.class public abstract Lwv/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/e0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ll2/e0;

    .line 2
    .line 3
    sget-object v1, Lwv/c;->f:Lwv/c;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ll2/e0;-><init>(Lay0/a;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lwv/f;->a:Ll2/e0;

    .line 9
    .line 10
    return-void
.end method

.method public static final a(Lx2/s;Lvv/n0;Lxf0/b2;Lt2/b;Ll2/o;I)V
    .locals 6

    .line 1
    check-cast p4, Ll2/t;

    .line 2
    .line 3
    const v0, 0x721f19c2

    .line 4
    .line 5
    .line 6
    invoke-virtual {p4, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p4, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    invoke-virtual {p4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    new-instance v0, Lwv/d;

    .line 16
    .line 17
    invoke-direct {v0, p0, p1, p2, p3}, Lwv/d;-><init>(Lx2/s;Lvv/n0;Lxf0/b2;Lt2/b;)V

    .line 18
    .line 19
    .line 20
    const v1, -0x41eaa30

    .line 21
    .line 22
    .line 23
    invoke-static {v1, p4, v0}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    const/4 v1, 0x6

    .line 28
    invoke-static {v0, p4, v1}, Lwv/f;->b(Lt2/b;Ll2/o;I)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p4}, Ll2/t;->s()Ll2/u1;

    .line 32
    .line 33
    .line 34
    move-result-object p4

    .line 35
    if-eqz p4, :cond_0

    .line 36
    .line 37
    new-instance v0, Lwv/d;

    .line 38
    .line 39
    move-object v1, p0

    .line 40
    move-object v2, p1

    .line 41
    move-object v3, p2

    .line 42
    move-object v4, p3

    .line 43
    move v5, p5

    .line 44
    invoke-direct/range {v0 .. v5}, Lwv/d;-><init>(Lx2/s;Lvv/n0;Lxf0/b2;Lt2/b;I)V

    .line 45
    .line 46
    .line 47
    iput-object v0, p4, Ll2/u1;->d:Lay0/n;

    .line 48
    .line 49
    :cond_0
    return-void
.end method

.method public static final b(Lt2/b;Ll2/o;I)V
    .locals 8

    .line 1
    move-object v5, p1

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p1, -0x66e61fe8

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p1, p2, 0xb

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    if-ne p1, v0, :cond_1

    .line 14
    .line 15
    invoke-virtual {v5}, Ll2/t;->A()Z

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-nez p1, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 23
    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_1
    :goto_0
    sget-object p1, Lwv/f;->a:Ll2/e0;

    .line 27
    .line 28
    invoke-virtual {v5, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    check-cast p1, Ljava/lang/Boolean;

    .line 33
    .line 34
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    const/4 v7, 0x0

    .line 39
    if-nez p1, :cond_2

    .line 40
    .line 41
    const p1, -0x16dcc1a9

    .line 42
    .line 43
    .line 44
    invoke-virtual {v5, p1}, Ll2/t;->Z(I)V

    .line 45
    .line 46
    .line 47
    sget-object v0, Lwv/e;->g:Lwv/e;

    .line 48
    .line 49
    sget-object v1, Lwv/b;->a:Lt2/b;

    .line 50
    .line 51
    sget-object v2, Lwv/e;->h:Lwv/e;

    .line 52
    .line 53
    sget-object v3, Lwv/b;->b:Lt2/b;

    .line 54
    .line 55
    new-instance p1, Lvv/w;

    .line 56
    .line 57
    const/4 v4, 0x5

    .line 58
    invoke-direct {p1, p0, v4}, Lvv/w;-><init>(Lt2/b;I)V

    .line 59
    .line 60
    .line 61
    const v4, 0x6817a71b

    .line 62
    .line 63
    .line 64
    invoke-static {v4, v5, p1}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    const/16 v6, 0x6c30

    .line 69
    .line 70
    invoke-static/range {v0 .. v6}, Llp/hc;->a(Lay0/n;Lay0/p;Lay0/n;Lay0/p;Lt2/b;Ll2/o;I)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v5, v7}, Ll2/t;->q(Z)V

    .line 74
    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_2
    const p1, -0x16dcbf93

    .line 78
    .line 79
    .line 80
    invoke-virtual {v5, p1}, Ll2/t;->Z(I)V

    .line 81
    .line 82
    .line 83
    const/4 p1, 0x6

    .line 84
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    invoke-virtual {p0, v5, p1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v5, v7}, Ll2/t;->q(Z)V

    .line 92
    .line 93
    .line 94
    :goto_1
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    if-eqz p1, :cond_3

    .line 99
    .line 100
    new-instance v0, Lvv/w;

    .line 101
    .line 102
    const/4 v1, 0x6

    .line 103
    invoke-direct {v0, p0, p2, v1}, Lvv/w;-><init>(Lt2/b;II)V

    .line 104
    .line 105
    .line 106
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 107
    .line 108
    :cond_3
    return-void
.end method
