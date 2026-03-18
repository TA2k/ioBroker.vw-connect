.class public final Lg71/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lx4/v;


# instance fields
.field public final d:Lg71/a;

.field public final e:I

.field public final f:I

.field public final g:I


# direct methods
.method public constructor <init>(Lg71/a;III)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lg71/c;->d:Lg71/a;

    .line 5
    .line 6
    iput p2, p0, Lg71/c;->e:I

    .line 7
    .line 8
    iput p3, p0, Lg71/c;->f:I

    .line 9
    .line 10
    iput p4, p0, Lg71/c;->g:I

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final F(Lt4/k;JLt4/m;J)J
    .locals 4

    .line 1
    const-string p2, "anchorBounds"

    .line 2
    .line 3
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p2, "layoutDirection"

    .line 7
    .line 8
    invoke-static {p4, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p2, p0, Lg71/c;->d:Lg71/a;

    .line 12
    .line 13
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 14
    .line 15
    .line 16
    move-result p2

    .line 17
    const/16 p3, 0x20

    .line 18
    .line 19
    const-wide v0, 0xffffffffL

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    if-eqz p2, :cond_1

    .line 25
    .line 26
    const/4 p4, 0x1

    .line 27
    if-ne p2, p4, :cond_0

    .line 28
    .line 29
    iget p2, p1, Lt4/k;->a:I

    .line 30
    .line 31
    invoke-virtual {p1}, Lt4/k;->d()I

    .line 32
    .line 33
    .line 34
    move-result p4

    .line 35
    div-int/lit8 p4, p4, 0x2

    .line 36
    .line 37
    add-int/2addr p4, p2

    .line 38
    iget p1, p1, Lt4/k;->b:I

    .line 39
    .line 40
    int-to-long v2, p4

    .line 41
    shl-long/2addr v2, p3

    .line 42
    int-to-long p1, p1

    .line 43
    and-long/2addr p1, v0

    .line 44
    or-long/2addr p1, v2

    .line 45
    shr-long v2, p5, p3

    .line 46
    .line 47
    long-to-int p4, v2

    .line 48
    div-int/lit8 p4, p4, 0x2

    .line 49
    .line 50
    and-long/2addr p5, v0

    .line 51
    long-to-int p5, p5

    .line 52
    int-to-long v2, p4

    .line 53
    shl-long/2addr v2, p3

    .line 54
    int-to-long p4, p5

    .line 55
    and-long/2addr p4, v0

    .line 56
    or-long/2addr p4, v2

    .line 57
    invoke-static {p1, p2, p4, p5}, Lt4/j;->c(JJ)J

    .line 58
    .line 59
    .line 60
    move-result-wide p1

    .line 61
    goto :goto_0

    .line 62
    :cond_0
    new-instance p0, La8/r0;

    .line 63
    .line 64
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 65
    .line 66
    .line 67
    throw p0

    .line 68
    :cond_1
    invoke-virtual {p1}, Lt4/k;->c()J

    .line 69
    .line 70
    .line 71
    move-result-wide v2

    .line 72
    iget p2, p0, Lg71/c;->e:I

    .line 73
    .line 74
    neg-int p2, p2

    .line 75
    iget p4, p0, Lg71/c;->f:I

    .line 76
    .line 77
    div-int/lit8 p4, p4, 0x2

    .line 78
    .line 79
    sub-int/2addr p2, p4

    .line 80
    invoke-virtual {p1}, Lt4/k;->d()I

    .line 81
    .line 82
    .line 83
    move-result p1

    .line 84
    div-int/lit8 p1, p1, 0x2

    .line 85
    .line 86
    add-int/2addr p1, p2

    .line 87
    and-long p4, p5, v0

    .line 88
    .line 89
    long-to-int p2, p4

    .line 90
    neg-int p2, p2

    .line 91
    int-to-long p4, p1

    .line 92
    shl-long/2addr p4, p3

    .line 93
    int-to-long p1, p2

    .line 94
    and-long/2addr p1, v0

    .line 95
    or-long/2addr p1, p4

    .line 96
    invoke-static {v2, v3, p1, p2}, Lt4/j;->d(JJ)J

    .line 97
    .line 98
    .line 99
    move-result-wide p1

    .line 100
    :goto_0
    const/4 p4, 0x0

    .line 101
    int-to-long p4, p4

    .line 102
    shl-long p3, p4, p3

    .line 103
    .line 104
    iget p0, p0, Lg71/c;->g:I

    .line 105
    .line 106
    int-to-long p5, p0

    .line 107
    and-long/2addr p5, v0

    .line 108
    or-long/2addr p3, p5

    .line 109
    invoke-static {p1, p2, p3, p4}, Lt4/j;->d(JJ)J

    .line 110
    .line 111
    .line 112
    move-result-wide p0

    .line 113
    return-wide p0
.end method
