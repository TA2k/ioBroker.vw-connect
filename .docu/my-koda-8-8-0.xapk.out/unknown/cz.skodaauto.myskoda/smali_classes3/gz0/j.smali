.class public final Lgz0/j;
.super Lgz0/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lqz0/g;
    with = Lmz0/k;
.end annotation


# static fields
.field public static final Companion:Lgz0/i;


# instance fields
.field public final b:J

.field public final c:Ljava/lang/String;

.field public final d:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lgz0/i;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lgz0/j;->Companion:Lgz0/i;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(J)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lgz0/j;->b:J

    .line 5
    .line 6
    const-wide/16 v0, 0x0

    .line 7
    .line 8
    cmp-long v2, p1, v0

    .line 9
    .line 10
    if-lez v2, :cond_5

    .line 11
    .line 12
    const-wide v2, 0x34630b8a000L

    .line 13
    .line 14
    .line 15
    .line 16
    .line 17
    rem-long v4, p1, v2

    .line 18
    .line 19
    cmp-long v4, v4, v0

    .line 20
    .line 21
    if-nez v4, :cond_0

    .line 22
    .line 23
    const-string v0, "HOUR"

    .line 24
    .line 25
    iput-object v0, p0, Lgz0/j;->c:Ljava/lang/String;

    .line 26
    .line 27
    div-long/2addr p1, v2

    .line 28
    iput-wide p1, p0, Lgz0/j;->d:J

    .line 29
    .line 30
    return-void

    .line 31
    :cond_0
    const-wide v2, 0xdf8475800L

    .line 32
    .line 33
    .line 34
    .line 35
    .line 36
    rem-long v4, p1, v2

    .line 37
    .line 38
    cmp-long v4, v4, v0

    .line 39
    .line 40
    if-nez v4, :cond_1

    .line 41
    .line 42
    const-string v0, "MINUTE"

    .line 43
    .line 44
    iput-object v0, p0, Lgz0/j;->c:Ljava/lang/String;

    .line 45
    .line 46
    div-long/2addr p1, v2

    .line 47
    iput-wide p1, p0, Lgz0/j;->d:J

    .line 48
    .line 49
    return-void

    .line 50
    :cond_1
    const v2, 0x3b9aca00

    .line 51
    .line 52
    .line 53
    int-to-long v2, v2

    .line 54
    rem-long v4, p1, v2

    .line 55
    .line 56
    cmp-long v4, v4, v0

    .line 57
    .line 58
    if-nez v4, :cond_2

    .line 59
    .line 60
    const-string v0, "SECOND"

    .line 61
    .line 62
    iput-object v0, p0, Lgz0/j;->c:Ljava/lang/String;

    .line 63
    .line 64
    div-long/2addr p1, v2

    .line 65
    iput-wide p1, p0, Lgz0/j;->d:J

    .line 66
    .line 67
    return-void

    .line 68
    :cond_2
    const v2, 0xf4240

    .line 69
    .line 70
    .line 71
    int-to-long v2, v2

    .line 72
    rem-long v4, p1, v2

    .line 73
    .line 74
    cmp-long v4, v4, v0

    .line 75
    .line 76
    if-nez v4, :cond_3

    .line 77
    .line 78
    const-string v0, "MILLISECOND"

    .line 79
    .line 80
    iput-object v0, p0, Lgz0/j;->c:Ljava/lang/String;

    .line 81
    .line 82
    div-long/2addr p1, v2

    .line 83
    iput-wide p1, p0, Lgz0/j;->d:J

    .line 84
    .line 85
    return-void

    .line 86
    :cond_3
    const/16 v2, 0x3e8

    .line 87
    .line 88
    int-to-long v2, v2

    .line 89
    rem-long v4, p1, v2

    .line 90
    .line 91
    cmp-long v0, v4, v0

    .line 92
    .line 93
    if-nez v0, :cond_4

    .line 94
    .line 95
    const-string v0, "MICROSECOND"

    .line 96
    .line 97
    iput-object v0, p0, Lgz0/j;->c:Ljava/lang/String;

    .line 98
    .line 99
    div-long/2addr p1, v2

    .line 100
    iput-wide p1, p0, Lgz0/j;->d:J

    .line 101
    .line 102
    return-void

    .line 103
    :cond_4
    const-string v0, "NANOSECOND"

    .line 104
    .line 105
    iput-object v0, p0, Lgz0/j;->c:Ljava/lang/String;

    .line 106
    .line 107
    iput-wide p1, p0, Lgz0/j;->d:J

    .line 108
    .line 109
    return-void

    .line 110
    :cond_5
    const-string p0, "Unit duration must be positive, but was "

    .line 111
    .line 112
    const-string v0, " ns."

    .line 113
    .line 114
    invoke-static {p1, p2, p0, v0}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 119
    .line 120
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    throw p1
.end method


# virtual methods
.method public final b(I)Lgz0/j;
    .locals 3

    .line 1
    new-instance v0, Lgz0/j;

    .line 2
    .line 3
    iget-wide v1, p0, Lgz0/j;->b:J

    .line 4
    .line 5
    int-to-long p0, p1

    .line 6
    invoke-static {v1, v2, p0, p1}, Ljava/lang/Math;->multiplyExact(JJ)J

    .line 7
    .line 8
    .line 9
    move-result-wide p0

    .line 10
    invoke-direct {v0, p0, p1}, Lgz0/j;-><init>(J)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-eq p0, p1, :cond_1

    .line 2
    .line 3
    instance-of v0, p1, Lgz0/j;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p1, Lgz0/j;

    .line 8
    .line 9
    iget-wide v0, p1, Lgz0/j;->b:J

    .line 10
    .line 11
    iget-wide p0, p0, Lgz0/j;->b:J

    .line 12
    .line 13
    cmp-long p0, p0, v0

    .line 14
    .line 15
    if-nez p0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return p0

    .line 20
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 21
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-wide v0, p0, Lgz0/j;->b:J

    .line 2
    .line 3
    long-to-int p0, v0

    .line 4
    const/16 v2, 0x20

    .line 5
    .line 6
    shr-long/2addr v0, v2

    .line 7
    long-to-int v0, v0

    .line 8
    xor-int/2addr p0, v0

    .line 9
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    const-string v0, "unit"

    .line 2
    .line 3
    iget-object v1, p0, Lgz0/j;->c:Ljava/lang/String;

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-wide/16 v2, 0x1

    .line 9
    .line 10
    iget-wide v4, p0, Lgz0/j;->d:J

    .line 11
    .line 12
    cmp-long p0, v4, v2

    .line 13
    .line 14
    if-nez p0, :cond_0

    .line 15
    .line 16
    return-object v1

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, v4, v5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const/16 v0, 0x2d

    .line 26
    .line 27
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method
