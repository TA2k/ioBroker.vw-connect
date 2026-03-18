.class public final Luj/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvc/b;


# static fields
.field public static final a:Luj/b;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Luj/b;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Luj/b;->a:Luj/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final F0(Lyj/b;Lyj/b;Ll2/o;I)V
    .locals 6

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, 0x3285327f

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p4, 0x6

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int/2addr v0, p4

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v0, p4

    .line 25
    :goto_1
    and-int/lit8 v1, p4, 0x30

    .line 26
    .line 27
    if-nez v1, :cond_3

    .line 28
    .line 29
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_2

    .line 34
    .line 35
    const/16 v1, 0x20

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_2
    const/16 v1, 0x10

    .line 39
    .line 40
    :goto_2
    or-int/2addr v0, v1

    .line 41
    :cond_3
    and-int/lit8 v1, v0, 0x13

    .line 42
    .line 43
    const/16 v2, 0x12

    .line 44
    .line 45
    if-eq v1, v2, :cond_4

    .line 46
    .line 47
    const/4 v1, 0x1

    .line 48
    goto :goto_3

    .line 49
    :cond_4
    const/4 v1, 0x0

    .line 50
    :goto_3
    and-int/lit8 v2, v0, 0x1

    .line 51
    .line 52
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_5

    .line 57
    .line 58
    and-int/lit8 v0, v0, 0x7e

    .line 59
    .line 60
    invoke-static {p1, p2, p3, v0}, Lxj/f;->k(Lyj/b;Lyj/b;Ll2/o;I)V

    .line 61
    .line 62
    .line 63
    goto :goto_4

    .line 64
    :cond_5
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 65
    .line 66
    .line 67
    :goto_4
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 68
    .line 69
    .line 70
    move-result-object p3

    .line 71
    if-eqz p3, :cond_6

    .line 72
    .line 73
    new-instance v0, Lph/a;

    .line 74
    .line 75
    const/16 v2, 0xd

    .line 76
    .line 77
    move-object v3, p0

    .line 78
    move-object v4, p1

    .line 79
    move-object v5, p2

    .line 80
    move v1, p4

    .line 81
    invoke-direct/range {v0 .. v5}, Lph/a;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 85
    .line 86
    :cond_6
    return-void
.end method

.method public final h0(ILay0/k;Ll2/o;Lwc/f;)V
    .locals 6

    .line 1
    const-string v0, "uiState"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

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
    const v0, 0x161218f4

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p3, p4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    const/4 v0, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x2

    .line 28
    :goto_0
    or-int/2addr v0, p1

    .line 29
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_1

    .line 34
    .line 35
    const/16 v1, 0x20

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/16 v1, 0x10

    .line 39
    .line 40
    :goto_1
    or-int/2addr v0, v1

    .line 41
    and-int/lit8 v1, v0, 0x13

    .line 42
    .line 43
    const/16 v2, 0x12

    .line 44
    .line 45
    if-eq v1, v2, :cond_2

    .line 46
    .line 47
    const/4 v1, 0x1

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/4 v1, 0x0

    .line 50
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 51
    .line 52
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_3

    .line 57
    .line 58
    and-int/lit8 v0, v0, 0x7e

    .line 59
    .line 60
    invoke-static {v0, p2, p3, p4}, Lvj/c;->g(ILay0/k;Ll2/o;Lwc/f;)V

    .line 61
    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_3
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 65
    .line 66
    .line 67
    :goto_3
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 68
    .line 69
    .line 70
    move-result-object p3

    .line 71
    if-eqz p3, :cond_4

    .line 72
    .line 73
    new-instance v0, Lqv0/f;

    .line 74
    .line 75
    const/16 v2, 0xf

    .line 76
    .line 77
    move-object v3, p0

    .line 78
    move v1, p1

    .line 79
    move-object v5, p2

    .line 80
    move-object v4, p4

    .line 81
    invoke-direct/range {v0 .. v5}, Lqv0/f;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 85
    .line 86
    :cond_4
    return-void
.end method

.method public final k(Llc/q;Lay0/k;Ll2/o;I)V
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
    const v0, -0x6eeeb9b

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    const/4 v0, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x2

    .line 28
    :goto_0
    or-int/2addr v0, p4

    .line 29
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_1

    .line 34
    .line 35
    const/16 v1, 0x20

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/16 v1, 0x10

    .line 39
    .line 40
    :goto_1
    or-int/2addr v0, v1

    .line 41
    and-int/lit8 v1, v0, 0x13

    .line 42
    .line 43
    const/16 v2, 0x12

    .line 44
    .line 45
    if-eq v1, v2, :cond_2

    .line 46
    .line 47
    const/4 v1, 0x1

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/4 v1, 0x0

    .line 50
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 51
    .line 52
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_3

    .line 57
    .line 58
    and-int/lit8 v1, v0, 0xe

    .line 59
    .line 60
    const/16 v2, 0x8

    .line 61
    .line 62
    or-int/2addr v1, v2

    .line 63
    and-int/lit8 v0, v0, 0x70

    .line 64
    .line 65
    or-int/2addr v0, v1

    .line 66
    invoke-static {p1, p2, p3, v0}, Lwj/c;->f(Llc/q;Lay0/k;Ll2/o;I)V

    .line 67
    .line 68
    .line 69
    goto :goto_3

    .line 70
    :cond_3
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 71
    .line 72
    .line 73
    :goto_3
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 74
    .line 75
    .line 76
    move-result-object p3

    .line 77
    if-eqz p3, :cond_4

    .line 78
    .line 79
    new-instance v0, Luj/a;

    .line 80
    .line 81
    const/4 v5, 0x1

    .line 82
    move-object v1, p0

    .line 83
    move-object v2, p1

    .line 84
    move-object v3, p2

    .line 85
    move v4, p4

    .line 86
    invoke-direct/range {v0 .. v5}, Luj/a;-><init>(Luj/b;Llc/q;Lay0/k;II)V

    .line 87
    .line 88
    .line 89
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 90
    .line 91
    :cond_4
    return-void
.end method

.method public final r0(Llc/q;Lay0/k;Ll2/o;I)V
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
    const v0, -0x70f5a142

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    const/4 v0, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x2

    .line 28
    :goto_0
    or-int/2addr v0, p4

    .line 29
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_1

    .line 34
    .line 35
    const/16 v1, 0x20

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/16 v1, 0x10

    .line 39
    .line 40
    :goto_1
    or-int/2addr v0, v1

    .line 41
    and-int/lit8 v1, v0, 0x13

    .line 42
    .line 43
    const/16 v2, 0x12

    .line 44
    .line 45
    if-eq v1, v2, :cond_2

    .line 46
    .line 47
    const/4 v1, 0x1

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/4 v1, 0x0

    .line 50
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 51
    .line 52
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_3

    .line 57
    .line 58
    and-int/lit8 v1, v0, 0xe

    .line 59
    .line 60
    const/16 v2, 0x8

    .line 61
    .line 62
    or-int/2addr v1, v2

    .line 63
    and-int/lit8 v0, v0, 0x70

    .line 64
    .line 65
    or-int/2addr v0, v1

    .line 66
    invoke-static {p1, p2, p3, v0}, Lxj/k;->r(Llc/q;Lay0/k;Ll2/o;I)V

    .line 67
    .line 68
    .line 69
    goto :goto_3

    .line 70
    :cond_3
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 71
    .line 72
    .line 73
    :goto_3
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 74
    .line 75
    .line 76
    move-result-object p3

    .line 77
    if-eqz p3, :cond_4

    .line 78
    .line 79
    new-instance v0, Luj/a;

    .line 80
    .line 81
    const/4 v5, 0x0

    .line 82
    move-object v1, p0

    .line 83
    move-object v2, p1

    .line 84
    move-object v3, p2

    .line 85
    move v4, p4

    .line 86
    invoke-direct/range {v0 .. v5}, Luj/a;-><init>(Luj/b;Llc/q;Lay0/k;II)V

    .line 87
    .line 88
    .line 89
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 90
    .line 91
    :cond_4
    return-void
.end method
