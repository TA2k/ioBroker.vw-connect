.class public final Lks0/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lzd0/a;


# direct methods
.method public constructor <init>(Lzd0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lks0/x;->a:Lzd0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/net/URI;)Lms0/f;
    .locals 11

    .line 1
    sget-object v0, Lms0/h;->e:Lms0/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-static {}, Lms0/h;->values()[Lms0/h;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    array-length v1, v0

    .line 11
    const/4 v2, 0x0

    .line 12
    move v3, v2

    .line 13
    :goto_0
    const/4 v4, 0x0

    .line 14
    if-ge v3, v1, :cond_1

    .line 15
    .line 16
    aget-object v5, v0, v3

    .line 17
    .line 18
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v6

    .line 22
    iget-object v7, v5, Lms0/h;->d:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v6, v7, v2}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 25
    .line 26
    .line 27
    move-result v6

    .line 28
    if-eqz v6, :cond_0

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    move-object v5, v4

    .line 35
    :goto_1
    const/4 p1, -0x1

    .line 36
    if-nez v5, :cond_2

    .line 37
    .line 38
    move v0, p1

    .line 39
    goto :goto_2

    .line 40
    :cond_2
    sget-object v0, Lks0/w;->a:[I

    .line 41
    .line 42
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    aget v0, v0, v1

    .line 47
    .line 48
    :goto_2
    if-eq v0, p1, :cond_6

    .line 49
    .line 50
    iget-object p0, p0, Lks0/x;->a:Lzd0/a;

    .line 51
    .line 52
    const/4 p1, 0x1

    .line 53
    if-eq v0, p1, :cond_5

    .line 54
    .line 55
    const/4 p1, 0x2

    .line 56
    if-eq v0, p1, :cond_5

    .line 57
    .line 58
    const/4 p1, 0x3

    .line 59
    if-eq v0, p1, :cond_4

    .line 60
    .line 61
    const/4 p1, 0x4

    .line 62
    if-ne v0, p1, :cond_3

    .line 63
    .line 64
    new-instance v5, Lne0/c;

    .line 65
    .line 66
    new-instance v6, Lls0/a;

    .line 67
    .line 68
    const-string p1, "Vehicle Activation Service was cancelled by user."

    .line 69
    .line 70
    invoke-direct {v6, p1, v4}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 71
    .line 72
    .line 73
    const/4 v9, 0x0

    .line 74
    const/16 v10, 0x1e

    .line 75
    .line 76
    const/4 v7, 0x0

    .line 77
    const/4 v8, 0x0

    .line 78
    invoke-direct/range {v5 .. v10}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p0, v5}, Lzd0/a;->a(Lne0/t;)V

    .line 82
    .line 83
    .line 84
    sget-object p0, Lms0/f;->e:Lms0/f;

    .line 85
    .line 86
    return-object p0

    .line 87
    :cond_3
    new-instance p0, La8/r0;

    .line 88
    .line 89
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :cond_4
    sget-object p0, Lms0/f;->d:Lms0/f;

    .line 94
    .line 95
    return-object p0

    .line 96
    :cond_5
    new-instance p1, Lne0/e;

    .line 97
    .line 98
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 99
    .line 100
    invoke-direct {p1, v0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {p0, p1}, Lzd0/a;->a(Lne0/t;)V

    .line 104
    .line 105
    .line 106
    sget-object p0, Lms0/f;->e:Lms0/f;

    .line 107
    .line 108
    return-object p0

    .line 109
    :cond_6
    new-instance p1, Ljv0/c;

    .line 110
    .line 111
    const/16 v0, 0x18

    .line 112
    .line 113
    invoke-direct {p1, v0}, Ljv0/c;-><init>(I)V

    .line 114
    .line 115
    .line 116
    invoke-static {v4, p0, p1}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 117
    .line 118
    .line 119
    sget-object p0, Lms0/f;->f:Lms0/f;

    .line 120
    .line 121
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ljava/net/URI;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lks0/x;->a(Ljava/net/URI;)Lms0/f;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
