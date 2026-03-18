.class public abstract Lgp/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/text/SimpleDateFormat;

.field public static final b:Ljava/lang/StringBuilder;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ljava/text/SimpleDateFormat;

    .line 2
    .line 3
    sget-object v1, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 4
    .line 5
    const-string v2, "MM-dd HH:mm:ss.SSS"

    .line 6
    .line 7
    invoke-direct {v0, v2, v1}, Ljava/text/SimpleDateFormat;-><init>(Ljava/lang/String;Ljava/util/Locale;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lgp/m;->a:Ljava/text/SimpleDateFormat;

    .line 11
    .line 12
    new-instance v0, Ljava/text/SimpleDateFormat;

    .line 13
    .line 14
    const-string v2, "MM-dd HH:mm:ss"

    .line 15
    .line 16
    invoke-direct {v0, v2, v1}, Ljava/text/SimpleDateFormat;-><init>(Ljava/lang/String;Ljava/util/Locale;)V

    .line 17
    .line 18
    .line 19
    new-instance v0, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const/16 v1, 0x21

    .line 22
    .line 23
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Lgp/m;->b:Ljava/lang/StringBuilder;

    .line 27
    .line 28
    return-void
.end method

.method public static a(JLjava/lang/StringBuilder;)V
    .locals 9

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v2, p0, v0

    .line 4
    .line 5
    if-nez v2, :cond_0

    .line 6
    .line 7
    const-string p0, "0s"

    .line 8
    .line 9
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->length()I

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    add-int/lit8 v3, v3, 0x1b

    .line 18
    .line 19
    invoke-virtual {p2, v3}, Ljava/lang/StringBuilder;->ensureCapacity(I)V

    .line 20
    .line 21
    .line 22
    const/4 v3, 0x1

    .line 23
    const/4 v4, 0x0

    .line 24
    if-gez v2, :cond_2

    .line 25
    .line 26
    const-string v2, "-"

    .line 27
    .line 28
    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-wide/high16 v5, -0x8000000000000000L

    .line 32
    .line 33
    cmp-long v2, p0, v5

    .line 34
    .line 35
    if-eqz v2, :cond_1

    .line 36
    .line 37
    neg-long p0, p0

    .line 38
    goto :goto_0

    .line 39
    :cond_1
    const-wide p0, 0x7fffffffffffffffL

    .line 40
    .line 41
    .line 42
    .line 43
    .line 44
    move v4, v3

    .line 45
    :cond_2
    :goto_0
    const-wide/32 v5, 0x5265c00

    .line 46
    .line 47
    .line 48
    cmp-long v2, p0, v5

    .line 49
    .line 50
    if-ltz v2, :cond_3

    .line 51
    .line 52
    div-long v7, p0, v5

    .line 53
    .line 54
    invoke-virtual {p2, v7, v8}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    const-string v2, "d"

    .line 58
    .line 59
    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    rem-long/2addr p0, v5

    .line 63
    :cond_3
    if-eq v3, v4, :cond_4

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_4
    const-wide/32 p0, 0x18c5c00

    .line 67
    .line 68
    .line 69
    :goto_1
    const-wide/32 v2, 0x36ee80

    .line 70
    .line 71
    .line 72
    cmp-long v4, p0, v2

    .line 73
    .line 74
    if-ltz v4, :cond_5

    .line 75
    .line 76
    div-long v4, p0, v2

    .line 77
    .line 78
    invoke-virtual {p2, v4, v5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const-string v4, "h"

    .line 82
    .line 83
    invoke-virtual {p2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    rem-long/2addr p0, v2

    .line 87
    :cond_5
    const-wide/32 v2, 0xea60

    .line 88
    .line 89
    .line 90
    cmp-long v4, p0, v2

    .line 91
    .line 92
    if-ltz v4, :cond_6

    .line 93
    .line 94
    div-long v4, p0, v2

    .line 95
    .line 96
    invoke-virtual {p2, v4, v5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    const-string v4, "m"

    .line 100
    .line 101
    invoke-virtual {p2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    rem-long/2addr p0, v2

    .line 105
    :cond_6
    const-wide/16 v2, 0x3e8

    .line 106
    .line 107
    cmp-long v4, p0, v2

    .line 108
    .line 109
    if-ltz v4, :cond_7

    .line 110
    .line 111
    div-long v4, p0, v2

    .line 112
    .line 113
    invoke-virtual {p2, v4, v5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    const-string v4, "s"

    .line 117
    .line 118
    invoke-virtual {p2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    rem-long/2addr p0, v2

    .line 122
    :cond_7
    cmp-long v0, p0, v0

    .line 123
    .line 124
    if-lez v0, :cond_8

    .line 125
    .line 126
    invoke-virtual {p2, p0, p1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    const-string p0, "ms"

    .line 130
    .line 131
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    :cond_8
    return-void
.end method
