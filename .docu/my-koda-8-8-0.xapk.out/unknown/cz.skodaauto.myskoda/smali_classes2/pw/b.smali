.class public final Lpw/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Lpw/b;

.field public static final f:Lpw/b;


# instance fields
.field public final a:J

.field public final b:Ljava/util/List;

.field public final c:J

.field public final d:J


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Lpw/b;

    .line 2
    .line 3
    const-wide v1, 0xff787878L

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const-wide v2, 0xff5a5a5aL

    .line 13
    .line 14
    .line 15
    .line 16
    .line 17
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    const-wide v3, 0xff383838L

    .line 22
    .line 23
    .line 24
    .line 25
    .line 26
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    filled-new-array {v1, v2, v3}, [Ljava/lang/Long;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    const-wide/32 v4, 0x47000000

    .line 39
    .line 40
    .line 41
    const-wide v6, 0xde000000L

    .line 42
    .line 43
    .line 44
    .line 45
    .line 46
    const-wide v1, 0xff212121L

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    invoke-direct/range {v0 .. v7}, Lpw/b;-><init>(JLjava/util/List;JJ)V

    .line 52
    .line 53
    .line 54
    sput-object v0, Lpw/b;->e:Lpw/b;

    .line 55
    .line 56
    new-instance v1, Lpw/b;

    .line 57
    .line 58
    const-wide v2, 0xffcacacaL

    .line 59
    .line 60
    .line 61
    .line 62
    .line 63
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    const-wide v2, 0xffa8a8a8L

    .line 68
    .line 69
    .line 70
    .line 71
    .line 72
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    const-wide v3, 0xff888888L

    .line 77
    .line 78
    .line 79
    .line 80
    .line 81
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 82
    .line 83
    .line 84
    move-result-object v3

    .line 85
    filled-new-array {v0, v2, v3}, [Ljava/lang/Long;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 90
    .line 91
    .line 92
    move-result-object v4

    .line 93
    const-wide v5, 0xff555555L

    .line 94
    .line 95
    .line 96
    .line 97
    .line 98
    const-wide v7, 0xffffffffL

    .line 99
    .line 100
    .line 101
    .line 102
    .line 103
    const-wide v2, 0xff8a8a8aL

    .line 104
    .line 105
    .line 106
    .line 107
    .line 108
    invoke-direct/range {v1 .. v8}, Lpw/b;-><init>(JLjava/util/List;JJ)V

    .line 109
    .line 110
    .line 111
    sput-object v1, Lpw/b;->f:Lpw/b;

    .line 112
    .line 113
    return-void
.end method

.method public constructor <init>(JLjava/util/List;JJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lpw/b;->a:J

    .line 5
    .line 6
    iput-object p3, p0, Lpw/b;->b:Ljava/util/List;

    .line 7
    .line 8
    iput-wide p4, p0, Lpw/b;->c:J

    .line 9
    .line 10
    iput-wide p6, p0, Lpw/b;->d:J

    .line 11
    .line 12
    return-void
.end method
