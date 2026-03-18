.class public final Lyt/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lqt/a;

.field public final b:D

.field public final c:D

.field public final d:Lyt/c;

.field public final e:Lyt/c;


# direct methods
.method public constructor <init>(Landroid/content/Context;Las/e;)V
    .locals 13

    .line 1
    new-instance v0, La61/a;

    .line 2
    .line 3
    const/16 v1, 0x1c

    .line 4
    .line 5
    invoke-direct {v0, v1}, La61/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ljava/util/Random;

    .line 9
    .line 10
    invoke-direct {v1}, Ljava/util/Random;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/util/Random;->nextDouble()D

    .line 14
    .line 15
    .line 16
    move-result-wide v1

    .line 17
    new-instance v3, Ljava/util/Random;

    .line 18
    .line 19
    invoke-direct {v3}, Ljava/util/Random;-><init>()V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v3}, Ljava/util/Random;->nextDouble()D

    .line 23
    .line 24
    .line 25
    move-result-wide v3

    .line 26
    invoke-static {}, Lqt/a;->e()Lqt/a;

    .line 27
    .line 28
    .line 29
    move-result-object v5

    .line 30
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 31
    .line 32
    .line 33
    const/4 v6, 0x0

    .line 34
    iput-object v6, p0, Lyt/d;->d:Lyt/c;

    .line 35
    .line 36
    iput-object v6, p0, Lyt/d;->e:Lyt/c;

    .line 37
    .line 38
    const-wide/16 v6, 0x0

    .line 39
    .line 40
    cmpg-double v8, v6, v1

    .line 41
    .line 42
    const/4 v9, 0x0

    .line 43
    const/4 v10, 0x1

    .line 44
    const-wide/high16 v11, 0x3ff0000000000000L    # 1.0

    .line 45
    .line 46
    if-gtz v8, :cond_0

    .line 47
    .line 48
    cmpg-double v8, v1, v11

    .line 49
    .line 50
    if-gez v8, :cond_0

    .line 51
    .line 52
    move v8, v10

    .line 53
    goto :goto_0

    .line 54
    :cond_0
    move v8, v9

    .line 55
    :goto_0
    if-eqz v8, :cond_3

    .line 56
    .line 57
    cmpg-double v6, v6, v3

    .line 58
    .line 59
    if-gtz v6, :cond_1

    .line 60
    .line 61
    cmpg-double v6, v3, v11

    .line 62
    .line 63
    if-gez v6, :cond_1

    .line 64
    .line 65
    move v9, v10

    .line 66
    :cond_1
    if-eqz v9, :cond_2

    .line 67
    .line 68
    iput-wide v1, p0, Lyt/d;->b:D

    .line 69
    .line 70
    iput-wide v3, p0, Lyt/d;->c:D

    .line 71
    .line 72
    iput-object v5, p0, Lyt/d;->a:Lqt/a;

    .line 73
    .line 74
    new-instance v1, Lyt/c;

    .line 75
    .line 76
    const-string v2, "Trace"

    .line 77
    .line 78
    invoke-direct {v1, p2, v0, v5, v2}, Lyt/c;-><init>(Las/e;La61/a;Lqt/a;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    iput-object v1, p0, Lyt/d;->d:Lyt/c;

    .line 82
    .line 83
    new-instance v1, Lyt/c;

    .line 84
    .line 85
    const-string v2, "Network"

    .line 86
    .line 87
    invoke-direct {v1, p2, v0, v5, v2}, Lyt/c;-><init>(Las/e;La61/a;Lqt/a;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    iput-object v1, p0, Lyt/d;->e:Lyt/c;

    .line 91
    .line 92
    invoke-static {p1}, Ljp/m1;->d(Landroid/content/Context;)Z

    .line 93
    .line 94
    .line 95
    return-void

    .line 96
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 97
    .line 98
    const-string p1, "Fragment sampling bucket ID should be in range [0.0, 1.0)."

    .line 99
    .line 100
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    throw p0

    .line 104
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 105
    .line 106
    const-string p1, "Sampling bucket ID should be in range [0.0, 1.0)."

    .line 107
    .line 108
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    throw p0
.end method

.method public static a(Lcom/google/protobuf/t;)Z
    .locals 2

    .line 1
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-lez v0, :cond_0

    .line 7
    .line 8
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Lau/w;

    .line 13
    .line 14
    invoke-virtual {v0}, Lau/w;->v()I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-lez v0, :cond_0

    .line 19
    .line 20
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    check-cast p0, Lau/w;

    .line 25
    .line 26
    invoke-virtual {p0}, Lau/w;->u()I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    const/4 v0, 0x2

    .line 31
    if-ne p0, v0, :cond_0

    .line 32
    .line 33
    const/4 p0, 0x1

    .line 34
    return p0

    .line 35
    :cond_0
    return v1
.end method
