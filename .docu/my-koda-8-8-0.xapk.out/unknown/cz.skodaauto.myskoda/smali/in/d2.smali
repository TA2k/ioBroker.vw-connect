.class public abstract Lin/d2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/HashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    const/16 v1, 0x9

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/util/HashMap;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lin/d2;->a:Ljava/util/HashMap;

    .line 9
    .line 10
    new-instance v2, Lin/e0;

    .line 11
    .line 12
    const/4 v3, 0x7

    .line 13
    const v4, 0x3f31a9fc    # 0.694f

    .line 14
    .line 15
    .line 16
    invoke-direct {v2, v3, v4}, Lin/e0;-><init>(IF)V

    .line 17
    .line 18
    .line 19
    const-string v4, "xx-small"

    .line 20
    .line 21
    invoke-virtual {v0, v4, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    new-instance v2, Lin/e0;

    .line 25
    .line 26
    const v4, 0x3f553f7d    # 0.833f

    .line 27
    .line 28
    .line 29
    invoke-direct {v2, v3, v4}, Lin/e0;-><init>(IF)V

    .line 30
    .line 31
    .line 32
    const-string v4, "x-small"

    .line 33
    .line 34
    invoke-virtual {v0, v4, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    new-instance v2, Lin/e0;

    .line 38
    .line 39
    const/high16 v4, 0x41200000    # 10.0f

    .line 40
    .line 41
    invoke-direct {v2, v3, v4}, Lin/e0;-><init>(IF)V

    .line 42
    .line 43
    .line 44
    const-string v4, "small"

    .line 45
    .line 46
    invoke-virtual {v0, v4, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    new-instance v2, Lin/e0;

    .line 50
    .line 51
    const/high16 v4, 0x41400000    # 12.0f

    .line 52
    .line 53
    invoke-direct {v2, v3, v4}, Lin/e0;-><init>(IF)V

    .line 54
    .line 55
    .line 56
    const-string v4, "medium"

    .line 57
    .line 58
    invoke-virtual {v0, v4, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    new-instance v2, Lin/e0;

    .line 62
    .line 63
    const v4, 0x41666666    # 14.4f

    .line 64
    .line 65
    .line 66
    invoke-direct {v2, v3, v4}, Lin/e0;-><init>(IF)V

    .line 67
    .line 68
    .line 69
    const-string v4, "large"

    .line 70
    .line 71
    invoke-virtual {v0, v4, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    new-instance v2, Lin/e0;

    .line 75
    .line 76
    const v4, 0x418a6666    # 17.3f

    .line 77
    .line 78
    .line 79
    invoke-direct {v2, v3, v4}, Lin/e0;-><init>(IF)V

    .line 80
    .line 81
    .line 82
    const-string v4, "x-large"

    .line 83
    .line 84
    invoke-virtual {v0, v4, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    new-instance v2, Lin/e0;

    .line 88
    .line 89
    const v4, 0x41a5999a    # 20.7f

    .line 90
    .line 91
    .line 92
    invoke-direct {v2, v3, v4}, Lin/e0;-><init>(IF)V

    .line 93
    .line 94
    .line 95
    const-string v3, "xx-large"

    .line 96
    .line 97
    invoke-virtual {v0, v3, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    new-instance v2, Lin/e0;

    .line 101
    .line 102
    const v3, 0x42a6a8f6    # 83.33f

    .line 103
    .line 104
    .line 105
    invoke-direct {v2, v1, v3}, Lin/e0;-><init>(IF)V

    .line 106
    .line 107
    .line 108
    const-string v3, "smaller"

    .line 109
    .line 110
    invoke-virtual {v0, v3, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    new-instance v2, Lin/e0;

    .line 114
    .line 115
    const/high16 v3, 0x42f00000    # 120.0f

    .line 116
    .line 117
    invoke-direct {v2, v1, v3}, Lin/e0;-><init>(IF)V

    .line 118
    .line 119
    .line 120
    const-string v1, "larger"

    .line 121
    .line 122
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    return-void
.end method
