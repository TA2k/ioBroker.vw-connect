.class public final Lf1/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lv2/o;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lv2/o;

    .line 5
    .line 6
    invoke-direct {v0}, Lv2/o;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lf1/e;->a:Lv2/o;

    .line 10
    .line 11
    return-void
.end method

.method public static b(Lf1/e;Lay0/n;Lt2/b;Lay0/a;I)V
    .locals 0

    .line 1
    and-int/lit8 p4, p4, 0x8

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    const/4 p2, 0x0

    .line 6
    :cond_0
    iget-object p0, p0, Lf1/e;->a:Lv2/o;

    .line 7
    .line 8
    new-instance p4, Lf1/d;

    .line 9
    .line 10
    invoke-direct {p4, p1, p2, p3}, Lf1/d;-><init>(Lay0/n;Lay0/o;Lay0/a;)V

    .line 11
    .line 12
    .line 13
    new-instance p1, Lt2/b;

    .line 14
    .line 15
    const/4 p2, 0x1

    .line 16
    const p3, 0x194839ac

    .line 17
    .line 18
    .line 19
    invoke-direct {p1, p4, p2, p3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, p1}, Lv2/o;->add(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a(Lf1/c;Ll2/o;I)V
    .locals 6

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, 0x4eb252f8

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x2

    .line 18
    :goto_0
    or-int/2addr v0, p3

    .line 19
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    const/16 v1, 0x20

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    const/16 v1, 0x10

    .line 29
    .line 30
    :goto_1
    or-int/2addr v0, v1

    .line 31
    and-int/lit8 v1, v0, 0x13

    .line 32
    .line 33
    const/16 v2, 0x12

    .line 34
    .line 35
    const/4 v3, 0x0

    .line 36
    if-eq v1, v2, :cond_2

    .line 37
    .line 38
    const/4 v1, 0x1

    .line 39
    goto :goto_2

    .line 40
    :cond_2
    move v1, v3

    .line 41
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 42
    .line 43
    invoke-virtual {p2, v2, v1}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_3

    .line 48
    .line 49
    iget-object v1, p0, Lf1/e;->a:Lv2/o;

    .line 50
    .line 51
    invoke-virtual {v1}, Lv2/o;->size()I

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    :goto_3
    if-ge v3, v2, :cond_4

    .line 56
    .line 57
    invoke-virtual {v1, v3}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    check-cast v4, Lay0/o;

    .line 62
    .line 63
    and-int/lit8 v5, v0, 0xe

    .line 64
    .line 65
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    invoke-interface {v4, p1, p2, v5}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    add-int/lit8 v3, v3, 0x1

    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_3
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 76
    .line 77
    .line 78
    :cond_4
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    if-eqz p2, :cond_5

    .line 83
    .line 84
    new-instance v0, Ld90/m;

    .line 85
    .line 86
    const/16 v1, 0xa

    .line 87
    .line 88
    invoke-direct {v0, p3, v1, p0, p1}, Ld90/m;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 92
    .line 93
    :cond_5
    return-void
.end method
