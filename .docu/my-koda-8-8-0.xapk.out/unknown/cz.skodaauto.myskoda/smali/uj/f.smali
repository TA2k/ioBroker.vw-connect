.class public final Luj/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcc/a;


# static fields
.field public static final a:Luj/f;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Luj/f;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Luj/f;->a:Luj/f;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Llc/q;Lay0/k;Ll2/o;I)V
    .locals 6

    .line 1
    const-string v0, "uiState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "event"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p3, Ll2/t;

    .line 12
    .line 13
    const v0, 0x4c2c36a3    # 4.5144716E7f

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, p4, 0x8

    .line 20
    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    :goto_0
    if-eqz v0, :cond_1

    .line 33
    .line 34
    const/4 v0, 0x4

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const/4 v0, 0x2

    .line 37
    :goto_1
    or-int/2addr v0, p4

    .line 38
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_2

    .line 43
    .line 44
    const/16 v1, 0x20

    .line 45
    .line 46
    goto :goto_2

    .line 47
    :cond_2
    const/16 v1, 0x10

    .line 48
    .line 49
    :goto_2
    or-int/2addr v0, v1

    .line 50
    and-int/lit8 v1, v0, 0x13

    .line 51
    .line 52
    const/16 v2, 0x12

    .line 53
    .line 54
    if-eq v1, v2, :cond_3

    .line 55
    .line 56
    const/4 v1, 0x1

    .line 57
    goto :goto_3

    .line 58
    :cond_3
    const/4 v1, 0x0

    .line 59
    :goto_3
    and-int/lit8 v2, v0, 0x1

    .line 60
    .line 61
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-eqz v1, :cond_4

    .line 66
    .line 67
    and-int/lit8 v1, v0, 0xe

    .line 68
    .line 69
    const/16 v2, 0x8

    .line 70
    .line 71
    or-int/2addr v1, v2

    .line 72
    and-int/lit8 v0, v0, 0x70

    .line 73
    .line 74
    or-int/2addr v0, v1

    .line 75
    invoke-static {p1, p2, p3, v0}, Lfk/f;->e(Llc/q;Lay0/k;Ll2/o;I)V

    .line 76
    .line 77
    .line 78
    goto :goto_4

    .line 79
    :cond_4
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 80
    .line 81
    .line 82
    :goto_4
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 83
    .line 84
    .line 85
    move-result-object p3

    .line 86
    if-eqz p3, :cond_5

    .line 87
    .line 88
    new-instance v0, Lph/a;

    .line 89
    .line 90
    const/16 v2, 0x11

    .line 91
    .line 92
    move-object v3, p0

    .line 93
    move-object v4, p1

    .line 94
    move-object v5, p2

    .line 95
    move v1, p4

    .line 96
    invoke-direct/range {v0 .. v5}, Lph/a;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 100
    .line 101
    :cond_5
    return-void
.end method

.method public final s(Lhc/a;Lay0/k;Ll2/o;I)V
    .locals 6

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p3, Ll2/t;

    .line 7
    .line 8
    const v0, 0x56b62522

    .line 9
    .line 10
    .line 11
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p4, 0x6

    .line 15
    .line 16
    if-nez v0, :cond_2

    .line 17
    .line 18
    and-int/lit8 v0, p4, 0x8

    .line 19
    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    :goto_0
    if-eqz v0, :cond_1

    .line 32
    .line 33
    const/4 v0, 0x4

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    const/4 v0, 0x2

    .line 36
    :goto_1
    or-int/2addr v0, p4

    .line 37
    goto :goto_2

    .line 38
    :cond_2
    move v0, p4

    .line 39
    :goto_2
    and-int/lit8 v1, p4, 0x30

    .line 40
    .line 41
    if-nez v1, :cond_4

    .line 42
    .line 43
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_3

    .line 48
    .line 49
    const/16 v1, 0x20

    .line 50
    .line 51
    goto :goto_3

    .line 52
    :cond_3
    const/16 v1, 0x10

    .line 53
    .line 54
    :goto_3
    or-int/2addr v0, v1

    .line 55
    :cond_4
    and-int/lit8 v1, v0, 0x13

    .line 56
    .line 57
    const/16 v2, 0x12

    .line 58
    .line 59
    if-eq v1, v2, :cond_5

    .line 60
    .line 61
    const/4 v1, 0x1

    .line 62
    goto :goto_4

    .line 63
    :cond_5
    const/4 v1, 0x0

    .line 64
    :goto_4
    and-int/lit8 v2, v0, 0x1

    .line 65
    .line 66
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-eqz v1, :cond_6

    .line 71
    .line 72
    and-int/lit8 v1, v0, 0xe

    .line 73
    .line 74
    const/16 v2, 0x8

    .line 75
    .line 76
    or-int/2addr v1, v2

    .line 77
    and-int/lit8 v0, v0, 0x70

    .line 78
    .line 79
    or-int/2addr v0, v1

    .line 80
    invoke-static {p1, p2, p3, v0}, Lfk/d;->a(Lhc/a;Lay0/k;Ll2/o;I)V

    .line 81
    .line 82
    .line 83
    goto :goto_5

    .line 84
    :cond_6
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 85
    .line 86
    .line 87
    :goto_5
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 88
    .line 89
    .line 90
    move-result-object p3

    .line 91
    if-eqz p3, :cond_7

    .line 92
    .line 93
    new-instance v0, Lph/a;

    .line 94
    .line 95
    const/16 v2, 0x12

    .line 96
    .line 97
    move-object v3, p0

    .line 98
    move-object v4, p1

    .line 99
    move-object v5, p2

    .line 100
    move v1, p4

    .line 101
    invoke-direct/range {v0 .. v5}, Lph/a;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 105
    .line 106
    :cond_7
    return-void
.end method
