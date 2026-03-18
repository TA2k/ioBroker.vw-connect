.class public abstract Lxw0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/TimeZone;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "GMT"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/TimeZone;->getTimeZone(Ljava/lang/String;)Ljava/util/TimeZone;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lxw0/a;->a:Ljava/util/TimeZone;

    .line 8
    .line 9
    return-void
.end method

.method public static final a(Ljava/lang/Long;)Lxw0/d;
    .locals 13

    .line 1
    sget-object v0, Lxw0/a;->a:Ljava/util/TimeZone;

    .line 2
    .line 3
    sget-object v1, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/util/Calendar;->getInstance(Ljava/util/TimeZone;Ljava/util/Locale;)Ljava/util/Calendar;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/lang/Number;->longValue()J

    .line 15
    .line 16
    .line 17
    move-result-wide v1

    .line 18
    invoke-virtual {v0, v1, v2}, Ljava/util/Calendar;->setTimeInMillis(J)V

    .line 19
    .line 20
    .line 21
    :cond_0
    const/16 p0, 0xf

    .line 22
    .line 23
    invoke-virtual {v0, p0}, Ljava/util/Calendar;->get(I)I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    const/16 v1, 0x10

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Ljava/util/Calendar;->get(I)I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    add-int/2addr v1, p0

    .line 34
    const/16 p0, 0xd

    .line 35
    .line 36
    invoke-virtual {v0, p0}, Ljava/util/Calendar;->get(I)I

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    const/16 p0, 0xc

    .line 41
    .line 42
    invoke-virtual {v0, p0}, Ljava/util/Calendar;->get(I)I

    .line 43
    .line 44
    .line 45
    move-result v4

    .line 46
    const/16 p0, 0xb

    .line 47
    .line 48
    invoke-virtual {v0, p0}, Ljava/util/Calendar;->get(I)I

    .line 49
    .line 50
    .line 51
    move-result v5

    .line 52
    const/4 p0, 0x7

    .line 53
    invoke-virtual {v0, p0}, Ljava/util/Calendar;->get(I)I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    const/4 v6, 0x5

    .line 58
    add-int/2addr v2, v6

    .line 59
    rem-int/2addr v2, p0

    .line 60
    sget-object p0, Lxw0/f;->d:Lwe0/b;

    .line 61
    .line 62
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    sget-object p0, Lxw0/f;->f:Lsx0/b;

    .line 66
    .line 67
    invoke-virtual {p0, v2}, Lsx0/b;->get(I)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    check-cast p0, Lxw0/f;

    .line 72
    .line 73
    invoke-virtual {v0, v6}, Ljava/util/Calendar;->get(I)I

    .line 74
    .line 75
    .line 76
    move-result v7

    .line 77
    const/4 v2, 0x6

    .line 78
    invoke-virtual {v0, v2}, Ljava/util/Calendar;->get(I)I

    .line 79
    .line 80
    .line 81
    move-result v8

    .line 82
    sget-object v2, Lxw0/e;->d:Lst/b;

    .line 83
    .line 84
    const/4 v6, 0x2

    .line 85
    invoke-virtual {v0, v6}, Ljava/util/Calendar;->get(I)I

    .line 86
    .line 87
    .line 88
    move-result v6

    .line 89
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 90
    .line 91
    .line 92
    sget-object v2, Lxw0/e;->f:Lsx0/b;

    .line 93
    .line 94
    invoke-virtual {v2, v6}, Lsx0/b;->get(I)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    move-object v9, v2

    .line 99
    check-cast v9, Lxw0/e;

    .line 100
    .line 101
    const/4 v2, 0x1

    .line 102
    invoke-virtual {v0, v2}, Ljava/util/Calendar;->get(I)I

    .line 103
    .line 104
    .line 105
    move-result v10

    .line 106
    new-instance v2, Lxw0/d;

    .line 107
    .line 108
    invoke-virtual {v0}, Ljava/util/Calendar;->getTimeInMillis()J

    .line 109
    .line 110
    .line 111
    move-result-wide v11

    .line 112
    int-to-long v0, v1

    .line 113
    add-long/2addr v11, v0

    .line 114
    move-object v6, p0

    .line 115
    invoke-direct/range {v2 .. v12}, Lxw0/d;-><init>(IIILxw0/f;IILxw0/e;IJ)V

    .line 116
    .line 117
    .line 118
    return-object v2
.end method
