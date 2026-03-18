.class public abstract Lcw0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/Set;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    sget-object v0, Low0/q;->a:Ljava/util/List;

    .line 2
    .line 3
    const-string v0, "If-Modified-Since"

    .line 4
    .line 5
    const-string v1, "If-Unmodified-Since"

    .line 6
    .line 7
    const-string v2, "Date"

    .line 8
    .line 9
    const-string v3, "Expires"

    .line 10
    .line 11
    const-string v4, "Last-Modified"

    .line 12
    .line 13
    filled-new-array {v2, v3, v4, v0, v1}, [Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Lcw0/k;->a:Ljava/util/Set;

    .line 22
    .line 23
    return-void
.end method

.method public static final a(Low0/o;Lrw0/d;Lay0/n;)V
    .locals 6

    .line 1
    new-instance v0, Low0/n;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Low0/n;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {v0, p0}, Lap0/o;->s(Low0/m;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p1}, Lrw0/d;->c()Low0/m;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {v0, v2}, Lap0/o;->s(Low0/m;)V

    .line 15
    .line 16
    .line 17
    new-instance v2, Low0/o;

    .line 18
    .line 19
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Ljava/util/Map;

    .line 22
    .line 23
    invoke-direct {v2, v0}, Low0/o;-><init>(Ljava/util/Map;)V

    .line 24
    .line 25
    .line 26
    new-instance v0, Lcw0/j;

    .line 27
    .line 28
    invoke-direct {v0, p2, v1, v1}, Lcw0/j;-><init>(Lay0/n;IB)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v2, v0}, Lvw0/l;->b(Lay0/n;)V

    .line 32
    .line 33
    .line 34
    sget-object v0, Low0/q;->a:Ljava/util/List;

    .line 35
    .line 36
    const-string v0, "User-Agent"

    .line 37
    .line 38
    invoke-virtual {p0, v0}, Lvw0/l;->get(Ljava/lang/String;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    if-nez v1, :cond_0

    .line 43
    .line 44
    invoke-virtual {p1}, Lrw0/d;->c()Low0/m;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-interface {v1, v0}, Lvw0/j;->get(Ljava/lang/String;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    if-nez v1, :cond_0

    .line 53
    .line 54
    sget v1, Lvw0/h;->a:I

    .line 55
    .line 56
    const-string v1, "ktor-client"

    .line 57
    .line 58
    invoke-interface {p2, v0, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    :cond_0
    invoke-virtual {p1}, Lrw0/d;->b()Low0/e;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    const-string v1, "Content-Type"

    .line 66
    .line 67
    if-eqz v0, :cond_1

    .line 68
    .line 69
    invoke-virtual {v0}, Lh/w;->toString()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    if-nez v0, :cond_2

    .line 74
    .line 75
    :cond_1
    invoke-virtual {p1}, Lrw0/d;->c()Low0/m;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    invoke-interface {v0, v1}, Lvw0/j;->get(Ljava/lang/String;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    if-nez v0, :cond_2

    .line 84
    .line 85
    invoke-virtual {p0, v1}, Lvw0/l;->get(Ljava/lang/String;)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    :cond_2
    invoke-virtual {p1}, Lrw0/d;->a()Ljava/lang/Long;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    const-string v3, "Content-Length"

    .line 94
    .line 95
    if-eqz v2, :cond_3

    .line 96
    .line 97
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 98
    .line 99
    .line 100
    move-result-wide v4

    .line 101
    invoke-static {v4, v5}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object v2

    .line 105
    if-nez v2, :cond_4

    .line 106
    .line 107
    :cond_3
    invoke-virtual {p1}, Lrw0/d;->c()Low0/m;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    invoke-interface {p1, v3}, Lvw0/j;->get(Ljava/lang/String;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    if-nez v2, :cond_4

    .line 116
    .line 117
    invoke-virtual {p0, v3}, Lvw0/l;->get(Ljava/lang/String;)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v2

    .line 121
    :cond_4
    if-eqz v0, :cond_5

    .line 122
    .line 123
    invoke-interface {p2, v1, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    :cond_5
    if-eqz v2, :cond_6

    .line 127
    .line 128
    invoke-interface {p2, v3, v2}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    :cond_6
    return-void
.end method
