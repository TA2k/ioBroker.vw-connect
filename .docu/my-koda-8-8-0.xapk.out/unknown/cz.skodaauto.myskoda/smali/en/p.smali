.class public abstract Len/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lb81/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "k"

    .line 2
    .line 3
    filled-new-array {v0}, [Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Lb81/c;->u([Ljava/lang/String;)Lb81/c;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Len/p;->a:Lb81/c;

    .line 12
    .line 13
    return-void
.end method

.method public static a(Lfn/a;Lum/a;FLen/d0;Z)Ljava/util/ArrayList;
    .locals 9

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lfn/a;->B()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    const/4 v2, 0x6

    .line 11
    if-ne v1, v2, :cond_0

    .line 12
    .line 13
    const-string p0, "Lottie doesn\'t support expressions."

    .line 14
    .line 15
    invoke-virtual {p1, p0}, Lum/a;->a(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    return-object v0

    .line 19
    :cond_0
    invoke-virtual {p0}, Lfn/a;->b()V

    .line 20
    .line 21
    .line 22
    :goto_0
    invoke-virtual {p0}, Lfn/a;->h()Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-eqz v1, :cond_5

    .line 27
    .line 28
    sget-object v1, Len/p;->a:Lb81/c;

    .line 29
    .line 30
    invoke-virtual {p0, v1}, Lfn/a;->H(Lb81/c;)I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-eqz v1, :cond_1

    .line 35
    .line 36
    invoke-virtual {p0}, Lfn/a;->T()V

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    invoke-virtual {p0}, Lfn/a;->B()I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    const/4 v2, 0x1

    .line 45
    if-ne v1, v2, :cond_4

    .line 46
    .line 47
    invoke-virtual {p0}, Lfn/a;->a()V

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0}, Lfn/a;->B()I

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    const/4 v2, 0x7

    .line 55
    if-ne v1, v2, :cond_2

    .line 56
    .line 57
    const/4 v7, 0x0

    .line 58
    move-object v3, p0

    .line 59
    move-object v4, p1

    .line 60
    move v5, p2

    .line 61
    move-object v6, p3

    .line 62
    move v8, p4

    .line 63
    invoke-static/range {v3 .. v8}, Len/o;->b(Lfn/a;Lum/a;FLen/d0;ZZ)Lhn/a;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    move-object v1, v3

    .line 68
    move-object v2, v4

    .line 69
    move v3, v5

    .line 70
    move-object v4, v6

    .line 71
    move v6, v8

    .line 72
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_2
    move-object v1, p0

    .line 77
    move-object v2, p1

    .line 78
    move v3, p2

    .line 79
    move-object v4, p3

    .line 80
    move v6, p4

    .line 81
    :goto_1
    invoke-virtual {v1}, Lfn/a;->h()Z

    .line 82
    .line 83
    .line 84
    move-result p0

    .line 85
    if-eqz p0, :cond_3

    .line 86
    .line 87
    const/4 v5, 0x1

    .line 88
    invoke-static/range {v1 .. v6}, Len/o;->b(Lfn/a;Lum/a;FLen/d0;ZZ)Lhn/a;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_3
    :goto_2
    invoke-virtual {v1}, Lfn/a;->d()V

    .line 97
    .line 98
    .line 99
    move-object p0, v1

    .line 100
    move-object p1, v2

    .line 101
    move p2, v3

    .line 102
    move-object p3, v4

    .line 103
    move p4, v6

    .line 104
    goto :goto_0

    .line 105
    :cond_4
    move-object v1, p0

    .line 106
    move-object v2, p1

    .line 107
    move v3, p2

    .line 108
    move-object v4, p3

    .line 109
    move v6, p4

    .line 110
    const/4 v5, 0x0

    .line 111
    invoke-static/range {v1 .. v6}, Len/o;->b(Lfn/a;Lum/a;FLen/d0;ZZ)Lhn/a;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-object p0, v1

    .line 119
    goto :goto_0

    .line 120
    :cond_5
    move-object v1, p0

    .line 121
    invoke-virtual {v1}, Lfn/a;->f()V

    .line 122
    .line 123
    .line 124
    invoke-static {v0}, Len/p;->b(Ljava/util/ArrayList;)V

    .line 125
    .line 126
    .line 127
    return-object v0
.end method

.method public static b(Ljava/util/ArrayList;)V
    .locals 5

    .line 1
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :cond_0
    :goto_0
    const/4 v2, 0x1

    .line 7
    add-int/lit8 v3, v0, -0x1

    .line 8
    .line 9
    if-ge v1, v3, :cond_1

    .line 10
    .line 11
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    check-cast v2, Lhn/a;

    .line 16
    .line 17
    add-int/lit8 v1, v1, 0x1

    .line 18
    .line 19
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    check-cast v3, Lhn/a;

    .line 24
    .line 25
    iget v4, v3, Lhn/a;->g:F

    .line 26
    .line 27
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    iput-object v4, v2, Lhn/a;->h:Ljava/lang/Float;

    .line 32
    .line 33
    iget-object v4, v2, Lhn/a;->c:Ljava/lang/Object;

    .line 34
    .line 35
    if-nez v4, :cond_0

    .line 36
    .line 37
    iget-object v3, v3, Lhn/a;->b:Ljava/lang/Object;

    .line 38
    .line 39
    if-eqz v3, :cond_0

    .line 40
    .line 41
    iput-object v3, v2, Lhn/a;->c:Ljava/lang/Object;

    .line 42
    .line 43
    instance-of v3, v2, Lxm/j;

    .line 44
    .line 45
    if-eqz v3, :cond_0

    .line 46
    .line 47
    check-cast v2, Lxm/j;

    .line 48
    .line 49
    invoke-virtual {v2}, Lxm/j;->d()V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    check-cast v0, Lhn/a;

    .line 58
    .line 59
    iget-object v1, v0, Lhn/a;->b:Ljava/lang/Object;

    .line 60
    .line 61
    if-eqz v1, :cond_2

    .line 62
    .line 63
    iget-object v1, v0, Lhn/a;->c:Ljava/lang/Object;

    .line 64
    .line 65
    if-nez v1, :cond_3

    .line 66
    .line 67
    :cond_2
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-le v1, v2, :cond_3

    .line 72
    .line 73
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    :cond_3
    return-void
.end method
