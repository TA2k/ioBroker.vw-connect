.class public abstract Lu/b1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh0/g;

.field public static final b:Lnx0/f;

.field public static final c:Lnx0/f;


# direct methods
.method static constructor <clinit>()V
    .locals 12

    .line 1
    const-wide/16 v0, 0x3

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-wide/16 v1, 0x4

    .line 8
    .line 9
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    sget-object v2, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 14
    .line 15
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    new-instance v3, Lh0/g;

    .line 19
    .line 20
    const-string v4, "camera2.streamSpec.streamUseCase"

    .line 21
    .line 22
    const/4 v5, 0x0

    .line 23
    invoke-direct {v3, v4, v2, v5}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 24
    .line 25
    .line 26
    sput-object v3, Lu/b1;->a:Lh0/g;

    .line 27
    .line 28
    new-instance v2, Lnx0/f;

    .line 29
    .line 30
    invoke-direct {v2}, Lnx0/f;-><init>()V

    .line 31
    .line 32
    .line 33
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 34
    .line 35
    sget-object v4, Lh0/q2;->g:Lh0/q2;

    .line 36
    .line 37
    sget-object v5, Lh0/q2;->d:Lh0/q2;

    .line 38
    .line 39
    sget-object v6, Lh0/q2;->e:Lh0/q2;

    .line 40
    .line 41
    const/16 v7, 0x21

    .line 42
    .line 43
    if-lt v3, v7, :cond_0

    .line 44
    .line 45
    sget-object v8, Lh0/q2;->i:Lh0/q2;

    .line 46
    .line 47
    sget-object v9, Lh0/q2;->f:Lh0/q2;

    .line 48
    .line 49
    filled-new-array {v6, v8, v9}, [Lh0/q2;

    .line 50
    .line 51
    .line 52
    move-result-object v10

    .line 53
    invoke-static {v10}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 54
    .line 55
    .line 56
    move-result-object v10

    .line 57
    invoke-virtual {v2, v1, v10}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    const-wide/16 v10, 0x1

    .line 61
    .line 62
    invoke-static {v10, v11}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 63
    .line 64
    .line 65
    move-result-object v10

    .line 66
    filled-new-array {v6, v8, v9}, [Lh0/q2;

    .line 67
    .line 68
    .line 69
    move-result-object v8

    .line 70
    invoke-static {v8}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 71
    .line 72
    .line 73
    move-result-object v8

    .line 74
    invoke-virtual {v2, v10, v8}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    const-wide/16 v8, 0x2

    .line 78
    .line 79
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 80
    .line 81
    .line 82
    move-result-object v8

    .line 83
    invoke-static {v5}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 84
    .line 85
    .line 86
    move-result-object v9

    .line 87
    invoke-virtual {v2, v8, v9}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    invoke-static {v4}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 91
    .line 92
    .line 93
    move-result-object v8

    .line 94
    invoke-virtual {v2, v0, v8}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    :cond_0
    invoke-virtual {v2}, Lnx0/f;->b()Lnx0/f;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    sput-object v2, Lu/b1;->b:Lnx0/f;

    .line 102
    .line 103
    new-instance v2, Lnx0/f;

    .line 104
    .line 105
    invoke-direct {v2}, Lnx0/f;-><init>()V

    .line 106
    .line 107
    .line 108
    if-lt v3, v7, :cond_1

    .line 109
    .line 110
    filled-new-array {v6, v5, v4}, [Lh0/q2;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    invoke-static {v3}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    invoke-virtual {v2, v1, v3}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    filled-new-array {v6, v4}, [Lh0/q2;

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    invoke-static {v1}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    invoke-virtual {v2, v0, v1}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    :cond_1
    invoke-virtual {v2}, Lnx0/f;->b()Lnx0/f;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    sput-object v0, Lu/b1;->c:Lnx0/f;

    .line 137
    .line 138
    return-void
.end method

.method public static a(Lh0/q0;Ljava/lang/Long;)Lt/a;
    .locals 2

    .line 1
    sget-object v0, Lu/b1;->a:Lh0/g;

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lh0/q0;->j(Lh0/g;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-interface {p0, v0}, Lh0/q0;->f(Lh0/g;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x0

    .line 20
    return-object p0

    .line 21
    :cond_0
    invoke-static {p0}, Lh0/j1;->h(Lh0/q0;)Lh0/j1;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-virtual {p0, v0, p1}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    new-instance p1, Lt/a;

    .line 29
    .line 30
    const/4 v0, 0x0

    .line 31
    invoke-direct {p1, p0, v0}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 32
    .line 33
    .line 34
    return-object p1
.end method

.method public static b(Lh0/q2;JLjava/util/List;)Z
    .locals 2

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x21

    .line 4
    .line 5
    if-ge v0, v1, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    sget-object v0, Lh0/q2;->h:Lh0/q2;

    .line 9
    .line 10
    if-ne p0, v0, :cond_4

    .line 11
    .line 12
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    sget-object v0, Lu/b1;->c:Lnx0/f;

    .line 17
    .line 18
    invoke-virtual {v0, p0}, Lnx0/f;->containsKey(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-nez p0, :cond_1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {v0, p0}, Lnx0/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    check-cast p0, Ljava/util/Set;

    .line 37
    .line 38
    invoke-interface {p3}, Ljava/util/List;->size()I

    .line 39
    .line 40
    .line 41
    move-result p1

    .line 42
    invoke-interface {p0}, Ljava/util/Set;->size()I

    .line 43
    .line 44
    .line 45
    move-result p2

    .line 46
    if-eq p1, p2, :cond_2

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_2
    invoke-interface {p3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    :cond_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    if-eqz p2, :cond_5

    .line 58
    .line 59
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    check-cast p2, Lh0/q2;

    .line 64
    .line 65
    invoke-interface {p0, p2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result p2

    .line 69
    if-nez p2, :cond_3

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_4
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 73
    .line 74
    .line 75
    move-result-object p3

    .line 76
    sget-object v0, Lu/b1;->b:Lnx0/f;

    .line 77
    .line 78
    invoke-virtual {v0, p3}, Lnx0/f;->containsKey(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result p3

    .line 82
    if-eqz p3, :cond_6

    .line 83
    .line 84
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    invoke-virtual {v0, p1}, Lnx0/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    check-cast p1, Ljava/util/Set;

    .line 96
    .line 97
    invoke-interface {p1, p0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result p0

    .line 101
    if-eqz p0, :cond_6

    .line 102
    .line 103
    :cond_5
    const/4 p0, 0x1

    .line 104
    return p0

    .line 105
    :cond_6
    :goto_0
    const/4 p0, 0x0

    .line 106
    return p0
.end method

.method public static c(Lh0/q0;Lh0/q2;)Z
    .locals 2

    .line 1
    sget-object v0, Lh0/o2;->X0:Lh0/g;

    .line 2
    .line 3
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-interface {p0, v0, v1}, Lh0/q0;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    check-cast v0, Ljava/lang/Boolean;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    sget-object v0, Lh0/y0;->e:Lh0/g;

    .line 22
    .line 23
    invoke-interface {p0, v0}, Lh0/q0;->j(Lh0/g;)Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-nez v1, :cond_1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    invoke-interface {p0, v0}, Lh0/q0;->f(Lh0/g;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    check-cast p0, Ljava/lang/Number;

    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    if-eqz p1, :cond_3

    .line 48
    .line 49
    const/4 p0, 0x3

    .line 50
    if-eq p1, p0, :cond_2

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    const-class p0, Landroidx/camera/camera2/internal/compat/quirk/PreviewUnderExposureQuirk;

    .line 54
    .line 55
    sget-object p1, Lx/a;->a:Ld01/x;

    .line 56
    .line 57
    invoke-virtual {p1, p0}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_3
    const/4 p1, 0x2

    .line 62
    if-ne p0, p1, :cond_4

    .line 63
    .line 64
    const/4 p0, 0x1

    .line 65
    return p0

    .line 66
    :cond_4
    :goto_0
    const/4 p0, 0x0

    .line 67
    return p0
.end method
