.class public final Lxv/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final synthetic a:J

.field public final synthetic b:Ll2/b1;


# direct methods
.method public constructor <init>(JLl2/b1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lxv/c;->a:J

    .line 5
    .line 6
    iput-object p3, p0, Lxv/c;->b:Ll2/b1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 5

    .line 1
    const-string p3, "$this$Layout"

    .line 2
    .line 3
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p3, "measurables"

    .line 7
    .line 8
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p2}, Lmx0/q;->k0(Ljava/util/List;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p2

    .line 15
    check-cast p2, Lt3/p0;

    .line 16
    .line 17
    sget-object p3, Lmx0/t;->d:Lmx0/t;

    .line 18
    .line 19
    if-eqz p2, :cond_1

    .line 20
    .line 21
    iget-wide v0, p0, Lxv/c;->a:J

    .line 22
    .line 23
    invoke-interface {p2, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    iget-object p0, p0, Lxv/c;->b:Ll2/b1;

    .line 28
    .line 29
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p4

    .line 33
    check-cast p4, Lt4/l;

    .line 34
    .line 35
    if-eqz p4, :cond_0

    .line 36
    .line 37
    iget v0, p2, Lt3/e1;->d:I

    .line 38
    .line 39
    iget-wide v1, p4, Lt4/l;->a:J

    .line 40
    .line 41
    const/16 p4, 0x20

    .line 42
    .line 43
    shr-long/2addr v1, p4

    .line 44
    long-to-int p4, v1

    .line 45
    if-ne v0, p4, :cond_0

    .line 46
    .line 47
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p4

    .line 51
    check-cast p4, Lt4/l;

    .line 52
    .line 53
    if-eqz p4, :cond_0

    .line 54
    .line 55
    iget v0, p2, Lt3/e1;->e:I

    .line 56
    .line 57
    iget-wide v1, p4, Lt4/l;->a:J

    .line 58
    .line 59
    const-wide v3, 0xffffffffL

    .line 60
    .line 61
    .line 62
    .line 63
    .line 64
    and-long/2addr v1, v3

    .line 65
    long-to-int p4, v1

    .line 66
    if-ne v0, p4, :cond_0

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_0
    iget p4, p2, Lt3/e1;->d:I

    .line 70
    .line 71
    iget v0, p2, Lt3/e1;->e:I

    .line 72
    .line 73
    invoke-static {p4, v0}, Lkp/f9;->a(II)J

    .line 74
    .line 75
    .line 76
    move-result-wide v0

    .line 77
    new-instance p4, Lt4/l;

    .line 78
    .line 79
    invoke-direct {p4, v0, v1}, Lt4/l;-><init>(J)V

    .line 80
    .line 81
    .line 82
    invoke-interface {p0, p4}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    :goto_0
    iget p0, p2, Lt3/e1;->d:I

    .line 86
    .line 87
    iget p4, p2, Lt3/e1;->e:I

    .line 88
    .line 89
    new-instance v0, Lb1/y;

    .line 90
    .line 91
    const/4 v1, 0x7

    .line 92
    invoke-direct {v0, p2, v1}, Lb1/y;-><init>(Lt3/e1;I)V

    .line 93
    .line 94
    .line 95
    invoke-interface {p1, p0, p4, p3, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    return-object p0

    .line 100
    :cond_1
    sget-object p0, Lxv/b;->g:Lxv/b;

    .line 101
    .line 102
    const/4 p2, 0x0

    .line 103
    invoke-interface {p1, p2, p2, p3, p0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0
.end method
