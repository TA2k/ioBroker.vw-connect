.class public final Ly61/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg61/g;


# instance fields
.field public final a:Lc71/g;

.field public final b:Lh70/o;


# direct methods
.method public constructor <init>(Lc71/g;Lh70/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ly61/g;->a:Lc71/g;

    .line 5
    .line 6
    iput-object p2, p0, Ly61/g;->b:Lh70/o;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ConnectionEstablishmentViewModel;Ll2/o;I)V
    .locals 6

    .line 1
    const-string v0, "modifier"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "viewModel"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p3, Ll2/t;

    .line 12
    .line 13
    const v0, -0x42de4415

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, p4, 0x6

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int/2addr v0, p4

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v0, p4

    .line 35
    :goto_1
    and-int/lit8 v1, p4, 0x30

    .line 36
    .line 37
    if-nez v1, :cond_3

    .line 38
    .line 39
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    const/16 v1, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v1, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v1

    .line 51
    :cond_3
    and-int/lit16 v1, p4, 0x180

    .line 52
    .line 53
    if-nez v1, :cond_6

    .line 54
    .line 55
    and-int/lit16 v1, p4, 0x200

    .line 56
    .line 57
    if-nez v1, :cond_4

    .line 58
    .line 59
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    goto :goto_3

    .line 64
    :cond_4
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    :goto_3
    if-eqz v1, :cond_5

    .line 69
    .line 70
    const/16 v1, 0x100

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_5
    const/16 v1, 0x80

    .line 74
    .line 75
    :goto_4
    or-int/2addr v0, v1

    .line 76
    :cond_6
    and-int/lit16 v1, v0, 0x93

    .line 77
    .line 78
    const/16 v2, 0x92

    .line 79
    .line 80
    if-eq v1, v2, :cond_7

    .line 81
    .line 82
    const/4 v1, 0x1

    .line 83
    goto :goto_5

    .line 84
    :cond_7
    const/4 v1, 0x0

    .line 85
    :goto_5
    and-int/lit8 v2, v0, 0x1

    .line 86
    .line 87
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    if-eqz v1, :cond_8

    .line 92
    .line 93
    new-instance v1, Ly61/c;

    .line 94
    .line 95
    invoke-direct {v1, p1, p2}, Ly61/c;-><init>(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ConnectionEstablishmentViewModel;)V

    .line 96
    .line 97
    .line 98
    const v2, -0x7815ba1

    .line 99
    .line 100
    .line 101
    invoke-static {v2, p3, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    and-int/lit16 v0, v0, 0x380

    .line 106
    .line 107
    or-int/lit8 v0, v0, 0x30

    .line 108
    .line 109
    iget-object v2, p0, Ly61/g;->b:Lh70/o;

    .line 110
    .line 111
    invoke-virtual {p0, v2, v1, p3, v0}, Ly61/g;->f(Lh70/o;Lt2/b;Ll2/o;I)V

    .line 112
    .line 113
    .line 114
    goto :goto_6

    .line 115
    :cond_8
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 116
    .line 117
    .line 118
    :goto_6
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 119
    .line 120
    .line 121
    move-result-object p3

    .line 122
    if-eqz p3, :cond_9

    .line 123
    .line 124
    new-instance v0, Lxk0/g0;

    .line 125
    .line 126
    const/4 v5, 0x2

    .line 127
    move-object v1, p0

    .line 128
    move-object v2, p1

    .line 129
    move-object v3, p2

    .line 130
    move v4, p4

    .line 131
    invoke-direct/range {v0 .. v5}, Lxk0/g0;-><init>(Ljava/lang/Object;Lx2/s;Ljava/lang/Object;II)V

    .line 132
    .line 133
    .line 134
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 135
    .line 136
    :cond_9
    return-void
.end method

.method public final b(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;Ll2/o;I)V
    .locals 6

    .line 1
    const-string v0, "modifier"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "viewModel"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p3, Ll2/t;

    .line 12
    .line 13
    const v0, 0x7f115acb

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, p4, 0x6

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int/2addr v0, p4

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v0, p4

    .line 35
    :goto_1
    and-int/lit8 v1, p4, 0x30

    .line 36
    .line 37
    if-nez v1, :cond_3

    .line 38
    .line 39
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    const/16 v1, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v1, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v1

    .line 51
    :cond_3
    and-int/lit16 v1, p4, 0x180

    .line 52
    .line 53
    if-nez v1, :cond_6

    .line 54
    .line 55
    and-int/lit16 v1, p4, 0x200

    .line 56
    .line 57
    if-nez v1, :cond_4

    .line 58
    .line 59
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    goto :goto_3

    .line 64
    :cond_4
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    :goto_3
    if-eqz v1, :cond_5

    .line 69
    .line 70
    const/16 v1, 0x100

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_5
    const/16 v1, 0x80

    .line 74
    .line 75
    :goto_4
    or-int/2addr v0, v1

    .line 76
    :cond_6
    and-int/lit16 v1, v0, 0x93

    .line 77
    .line 78
    const/16 v2, 0x92

    .line 79
    .line 80
    if-eq v1, v2, :cond_7

    .line 81
    .line 82
    const/4 v1, 0x1

    .line 83
    goto :goto_5

    .line 84
    :cond_7
    const/4 v1, 0x0

    .line 85
    :goto_5
    and-int/lit8 v2, v0, 0x1

    .line 86
    .line 87
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    if-eqz v1, :cond_8

    .line 92
    .line 93
    new-instance v1, Ly61/f;

    .line 94
    .line 95
    invoke-direct {v1, p1, p2}, Ly61/f;-><init>(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;)V

    .line 96
    .line 97
    .line 98
    const v2, -0x5fea54c1

    .line 99
    .line 100
    .line 101
    invoke-static {v2, p3, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    and-int/lit16 v0, v0, 0x380

    .line 106
    .line 107
    or-int/lit8 v0, v0, 0x30

    .line 108
    .line 109
    iget-object v2, p0, Ly61/g;->b:Lh70/o;

    .line 110
    .line 111
    invoke-virtual {p0, v2, v1, p3, v0}, Ly61/g;->f(Lh70/o;Lt2/b;Ll2/o;I)V

    .line 112
    .line 113
    .line 114
    goto :goto_6

    .line 115
    :cond_8
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 116
    .line 117
    .line 118
    :goto_6
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 119
    .line 120
    .line 121
    move-result-object p3

    .line 122
    if-eqz p3, :cond_9

    .line 123
    .line 124
    new-instance v0, Lxk0/g0;

    .line 125
    .line 126
    const/16 v5, 0x8

    .line 127
    .line 128
    move-object v1, p0

    .line 129
    move-object v2, p1

    .line 130
    move-object v3, p2

    .line 131
    move v4, p4

    .line 132
    invoke-direct/range {v0 .. v5}, Lxk0/g0;-><init>(Ljava/lang/Object;Lx2/s;Ljava/lang/Object;II)V

    .line 133
    .line 134
    .line 135
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 136
    .line 137
    :cond_9
    return-void
.end method

.method public final c(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;Ll2/o;I)V
    .locals 6

    .line 1
    const-string v0, "modifier"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "viewModel"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p3, Ll2/t;

    .line 12
    .line 13
    const v0, 0x314043cb

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, p4, 0x6

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int/2addr v0, p4

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v0, p4

    .line 35
    :goto_1
    and-int/lit8 v1, p4, 0x30

    .line 36
    .line 37
    if-nez v1, :cond_3

    .line 38
    .line 39
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    const/16 v1, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v1, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v1

    .line 51
    :cond_3
    and-int/lit16 v1, p4, 0x180

    .line 52
    .line 53
    if-nez v1, :cond_6

    .line 54
    .line 55
    and-int/lit16 v1, p4, 0x200

    .line 56
    .line 57
    if-nez v1, :cond_4

    .line 58
    .line 59
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    goto :goto_3

    .line 64
    :cond_4
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    :goto_3
    if-eqz v1, :cond_5

    .line 69
    .line 70
    const/16 v1, 0x100

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_5
    const/16 v1, 0x80

    .line 74
    .line 75
    :goto_4
    or-int/2addr v0, v1

    .line 76
    :cond_6
    and-int/lit16 v1, v0, 0x93

    .line 77
    .line 78
    const/16 v2, 0x92

    .line 79
    .line 80
    if-eq v1, v2, :cond_7

    .line 81
    .line 82
    const/4 v1, 0x1

    .line 83
    goto :goto_5

    .line 84
    :cond_7
    const/4 v1, 0x0

    .line 85
    :goto_5
    and-int/lit8 v2, v0, 0x1

    .line 86
    .line 87
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    if-eqz v1, :cond_8

    .line 92
    .line 93
    new-instance v1, La71/v;

    .line 94
    .line 95
    invoke-direct {v1, p1, p2}, La71/v;-><init>(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;)V

    .line 96
    .line 97
    .line 98
    const v2, 0x5244943f

    .line 99
    .line 100
    .line 101
    invoke-static {v2, p3, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    and-int/lit16 v0, v0, 0x380

    .line 106
    .line 107
    or-int/lit8 v0, v0, 0x30

    .line 108
    .line 109
    iget-object v2, p0, Ly61/g;->b:Lh70/o;

    .line 110
    .line 111
    invoke-virtual {p0, v2, v1, p3, v0}, Ly61/g;->f(Lh70/o;Lt2/b;Ll2/o;I)V

    .line 112
    .line 113
    .line 114
    goto :goto_6

    .line 115
    :cond_8
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 116
    .line 117
    .line 118
    :goto_6
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 119
    .line 120
    .line 121
    move-result-object p3

    .line 122
    if-eqz p3, :cond_9

    .line 123
    .line 124
    new-instance v0, Lxk0/g0;

    .line 125
    .line 126
    const/4 v5, 0x7

    .line 127
    move-object v1, p0

    .line 128
    move-object v2, p1

    .line 129
    move-object v3, p2

    .line 130
    move v4, p4

    .line 131
    invoke-direct/range {v0 .. v5}, Lxk0/g0;-><init>(Ljava/lang/Object;Lx2/s;Ljava/lang/Object;II)V

    .line 132
    .line 133
    .line 134
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 135
    .line 136
    :cond_9
    return-void
.end method

.method public final d(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFailedViewModel;Ll2/o;I)V
    .locals 6

    .line 1
    const-string v0, "modifier"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "viewModel"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p3, Ll2/t;

    .line 12
    .line 13
    const v0, -0x1bb68a15

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, p4, 0x6

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int/2addr v0, p4

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v0, p4

    .line 35
    :goto_1
    and-int/lit8 v1, p4, 0x30

    .line 36
    .line 37
    if-nez v1, :cond_3

    .line 38
    .line 39
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    const/16 v1, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v1, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v1

    .line 51
    :cond_3
    and-int/lit16 v1, p4, 0x180

    .line 52
    .line 53
    if-nez v1, :cond_6

    .line 54
    .line 55
    and-int/lit16 v1, p4, 0x200

    .line 56
    .line 57
    if-nez v1, :cond_4

    .line 58
    .line 59
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    goto :goto_3

    .line 64
    :cond_4
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    :goto_3
    if-eqz v1, :cond_5

    .line 69
    .line 70
    const/16 v1, 0x100

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_5
    const/16 v1, 0x80

    .line 74
    .line 75
    :goto_4
    or-int/2addr v0, v1

    .line 76
    :cond_6
    and-int/lit16 v1, v0, 0x93

    .line 77
    .line 78
    const/16 v2, 0x92

    .line 79
    .line 80
    if-eq v1, v2, :cond_7

    .line 81
    .line 82
    const/4 v1, 0x1

    .line 83
    goto :goto_5

    .line 84
    :cond_7
    const/4 v1, 0x0

    .line 85
    :goto_5
    and-int/lit8 v2, v0, 0x1

    .line 86
    .line 87
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    if-eqz v1, :cond_8

    .line 92
    .line 93
    new-instance v1, Ly61/d;

    .line 94
    .line 95
    invoke-direct {v1, p1, p2}, Ly61/d;-><init>(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFailedViewModel;)V

    .line 96
    .line 97
    .line 98
    const v2, 0x1650205f

    .line 99
    .line 100
    .line 101
    invoke-static {v2, p3, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    and-int/lit16 v0, v0, 0x380

    .line 106
    .line 107
    or-int/lit8 v0, v0, 0x30

    .line 108
    .line 109
    iget-object v2, p0, Ly61/g;->b:Lh70/o;

    .line 110
    .line 111
    invoke-virtual {p0, v2, v1, p3, v0}, Ly61/g;->f(Lh70/o;Lt2/b;Ll2/o;I)V

    .line 112
    .line 113
    .line 114
    goto :goto_6

    .line 115
    :cond_8
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 116
    .line 117
    .line 118
    :goto_6
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 119
    .line 120
    .line 121
    move-result-object p3

    .line 122
    if-eqz p3, :cond_9

    .line 123
    .line 124
    new-instance v0, Lxk0/g0;

    .line 125
    .line 126
    const/4 v5, 0x3

    .line 127
    move-object v1, p0

    .line 128
    move-object v2, p1

    .line 129
    move-object v3, p2

    .line 130
    move v4, p4

    .line 131
    invoke-direct/range {v0 .. v5}, Lxk0/g0;-><init>(Ljava/lang/Object;Lx2/s;Ljava/lang/Object;II)V

    .line 132
    .line 133
    .line 134
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 135
    .line 136
    :cond_9
    return-void
.end method

.method public final e(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;Ll2/o;I)V
    .locals 6

    .line 1
    const-string v0, "modifier"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "viewModel"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p3, Ll2/t;

    .line 12
    .line 13
    const v0, 0x1e79c40b

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, p4, 0x6

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int/2addr v0, p4

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v0, p4

    .line 35
    :goto_1
    and-int/lit8 v1, p4, 0x30

    .line 36
    .line 37
    if-nez v1, :cond_3

    .line 38
    .line 39
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    const/16 v1, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v1, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v1

    .line 51
    :cond_3
    and-int/lit16 v1, p4, 0x180

    .line 52
    .line 53
    if-nez v1, :cond_6

    .line 54
    .line 55
    and-int/lit16 v1, p4, 0x200

    .line 56
    .line 57
    if-nez v1, :cond_4

    .line 58
    .line 59
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    goto :goto_3

    .line 64
    :cond_4
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    :goto_3
    if-eqz v1, :cond_5

    .line 69
    .line 70
    const/16 v1, 0x100

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_5
    const/16 v1, 0x80

    .line 74
    .line 75
    :goto_4
    or-int/2addr v0, v1

    .line 76
    :cond_6
    and-int/lit16 v1, v0, 0x93

    .line 77
    .line 78
    const/16 v2, 0x92

    .line 79
    .line 80
    if-eq v1, v2, :cond_7

    .line 81
    .line 82
    const/4 v1, 0x1

    .line 83
    goto :goto_5

    .line 84
    :cond_7
    const/4 v1, 0x0

    .line 85
    :goto_5
    and-int/lit8 v2, v0, 0x1

    .line 86
    .line 87
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    if-eqz v1, :cond_8

    .line 92
    .line 93
    new-instance v1, Lb71/c;

    .line 94
    .line 95
    invoke-direct {v1, p1, p2}, Lb71/c;-><init>(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;)V

    .line 96
    .line 97
    .line 98
    const v2, 0x3f7e147f

    .line 99
    .line 100
    .line 101
    invoke-static {v2, p3, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    and-int/lit16 v0, v0, 0x380

    .line 106
    .line 107
    or-int/lit8 v0, v0, 0x30

    .line 108
    .line 109
    iget-object v2, p0, Ly61/g;->b:Lh70/o;

    .line 110
    .line 111
    invoke-virtual {p0, v2, v1, p3, v0}, Ly61/g;->f(Lh70/o;Lt2/b;Ll2/o;I)V

    .line 112
    .line 113
    .line 114
    goto :goto_6

    .line 115
    :cond_8
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 116
    .line 117
    .line 118
    :goto_6
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 119
    .line 120
    .line 121
    move-result-object p3

    .line 122
    if-eqz p3, :cond_9

    .line 123
    .line 124
    new-instance v0, Lxk0/g0;

    .line 125
    .line 126
    const/16 v5, 0x9

    .line 127
    .line 128
    move-object v1, p0

    .line 129
    move-object v2, p1

    .line 130
    move-object v3, p2

    .line 131
    move v4, p4

    .line 132
    invoke-direct/range {v0 .. v5}, Lxk0/g0;-><init>(Ljava/lang/Object;Lx2/s;Ljava/lang/Object;II)V

    .line 133
    .line 134
    .line 135
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 136
    .line 137
    :cond_9
    return-void
.end method

.method public final f(Lh70/o;Lt2/b;Ll2/o;I)V
    .locals 6

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, 0x79a2bc49

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
    if-nez v0, :cond_2

    .line 12
    .line 13
    and-int/lit8 v0, p4, 0x8

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    :goto_0
    if-eqz v0, :cond_1

    .line 27
    .line 28
    const/4 v0, 0x4

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/4 v0, 0x2

    .line 31
    :goto_1
    or-int/2addr v0, p4

    .line 32
    goto :goto_2

    .line 33
    :cond_2
    move v0, p4

    .line 34
    :goto_2
    and-int/lit8 v1, p4, 0x30

    .line 35
    .line 36
    if-nez v1, :cond_4

    .line 37
    .line 38
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_3

    .line 43
    .line 44
    const/16 v1, 0x20

    .line 45
    .line 46
    goto :goto_3

    .line 47
    :cond_3
    const/16 v1, 0x10

    .line 48
    .line 49
    :goto_3
    or-int/2addr v0, v1

    .line 50
    :cond_4
    and-int/lit16 v1, p4, 0x180

    .line 51
    .line 52
    if-nez v1, :cond_7

    .line 53
    .line 54
    and-int/lit16 v1, p4, 0x200

    .line 55
    .line 56
    if-nez v1, :cond_5

    .line 57
    .line 58
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    goto :goto_4

    .line 63
    :cond_5
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    :goto_4
    if-eqz v1, :cond_6

    .line 68
    .line 69
    const/16 v1, 0x100

    .line 70
    .line 71
    goto :goto_5

    .line 72
    :cond_6
    const/16 v1, 0x80

    .line 73
    .line 74
    :goto_5
    or-int/2addr v0, v1

    .line 75
    :cond_7
    and-int/lit16 v1, v0, 0x93

    .line 76
    .line 77
    const/16 v2, 0x92

    .line 78
    .line 79
    const/4 v3, 0x1

    .line 80
    if-eq v1, v2, :cond_8

    .line 81
    .line 82
    move v1, v3

    .line 83
    goto :goto_6

    .line 84
    :cond_8
    const/4 v1, 0x0

    .line 85
    :goto_6
    and-int/2addr v0, v3

    .line 86
    invoke-virtual {p3, v0, v1}, Ll2/t;->O(IZ)Z

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    if-eqz v0, :cond_9

    .line 91
    .line 92
    new-instance v0, Ly61/e;

    .line 93
    .line 94
    const/4 v1, 0x0

    .line 95
    invoke-direct {v0, p1, p0, p2, v1}, Ly61/e;-><init>(Lh70/o;Ly61/g;Lt2/b;I)V

    .line 96
    .line 97
    .line 98
    const v1, -0x7c6cd908

    .line 99
    .line 100
    .line 101
    invoke-static {v1, p3, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    const/4 v1, 0x6

    .line 106
    invoke-static {v0, p3, v1}, Li71/c;->a(Lt2/b;Ll2/o;I)V

    .line 107
    .line 108
    .line 109
    goto :goto_7

    .line 110
    :cond_9
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 111
    .line 112
    .line 113
    :goto_7
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 114
    .line 115
    .line 116
    move-result-object p3

    .line 117
    if-eqz p3, :cond_a

    .line 118
    .line 119
    new-instance v0, Lxk0/g0;

    .line 120
    .line 121
    const/4 v2, 0x4

    .line 122
    move-object v3, p0

    .line 123
    move-object v4, p1

    .line 124
    move-object v5, p2

    .line 125
    move v1, p4

    .line 126
    invoke-direct/range {v0 .. v5}, Lxk0/g0;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 130
    .line 131
    :cond_a
    return-void
.end method

.method public final g(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;Ll2/o;I)V
    .locals 6

    .line 1
    const-string v0, "modifier"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "viewModel"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p3, Ll2/t;

    .line 12
    .line 13
    const v0, -0x24797a55

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, p4, 0x6

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int/2addr v0, p4

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v0, p4

    .line 35
    :goto_1
    and-int/lit8 v1, p4, 0x30

    .line 36
    .line 37
    if-nez v1, :cond_3

    .line 38
    .line 39
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    const/16 v1, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v1, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v1

    .line 51
    :cond_3
    and-int/lit16 v1, p4, 0x180

    .line 52
    .line 53
    if-nez v1, :cond_6

    .line 54
    .line 55
    and-int/lit16 v1, p4, 0x200

    .line 56
    .line 57
    if-nez v1, :cond_4

    .line 58
    .line 59
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    goto :goto_3

    .line 64
    :cond_4
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    :goto_3
    if-eqz v1, :cond_5

    .line 69
    .line 70
    const/16 v1, 0x100

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_5
    const/16 v1, 0x80

    .line 74
    .line 75
    :goto_4
    or-int/2addr v0, v1

    .line 76
    :cond_6
    and-int/lit16 v1, v0, 0x93

    .line 77
    .line 78
    const/16 v2, 0x92

    .line 79
    .line 80
    if-eq v1, v2, :cond_7

    .line 81
    .line 82
    const/4 v1, 0x1

    .line 83
    goto :goto_5

    .line 84
    :cond_7
    const/4 v1, 0x0

    .line 85
    :goto_5
    and-int/lit8 v2, v0, 0x1

    .line 86
    .line 87
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    if-eqz v1, :cond_8

    .line 92
    .line 93
    new-instance v1, La71/p0;

    .line 94
    .line 95
    invoke-direct {v1, p1, p2}, La71/p0;-><init>(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;)V

    .line 96
    .line 97
    .line 98
    const v2, -0x2b6debe1

    .line 99
    .line 100
    .line 101
    invoke-static {v2, p3, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    and-int/lit16 v0, v0, 0x380

    .line 106
    .line 107
    or-int/lit8 v0, v0, 0x30

    .line 108
    .line 109
    iget-object v2, p0, Ly61/g;->b:Lh70/o;

    .line 110
    .line 111
    invoke-virtual {p0, v2, v1, p3, v0}, Ly61/g;->f(Lh70/o;Lt2/b;Ll2/o;I)V

    .line 112
    .line 113
    .line 114
    goto :goto_6

    .line 115
    :cond_8
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 116
    .line 117
    .line 118
    :goto_6
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 119
    .line 120
    .line 121
    move-result-object p3

    .line 122
    if-eqz p3, :cond_9

    .line 123
    .line 124
    new-instance v0, Lxk0/g0;

    .line 125
    .line 126
    const/4 v5, 0x6

    .line 127
    move-object v1, p0

    .line 128
    move-object v2, p1

    .line 129
    move-object v3, p2

    .line 130
    move v4, p4

    .line 131
    invoke-direct/range {v0 .. v5}, Lxk0/g0;-><init>(Ljava/lang/Object;Lx2/s;Ljava/lang/Object;II)V

    .line 132
    .line 133
    .line 134
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 135
    .line 136
    :cond_9
    return-void
.end method

.method public final h(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;Ll2/o;I)V
    .locals 6

    .line 1
    const-string v0, "modifier"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "viewModel"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p3, Ll2/t;

    .line 12
    .line 13
    const v0, -0x4bc64b6b

    .line 14
    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, p4, 0x6

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int/2addr v0, p4

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v0, p4

    .line 35
    :goto_1
    and-int/lit8 v1, p4, 0x30

    .line 36
    .line 37
    if-nez v1, :cond_3

    .line 38
    .line 39
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    const/16 v1, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v1, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v1

    .line 51
    :cond_3
    and-int/lit16 v1, p4, 0x180

    .line 52
    .line 53
    if-nez v1, :cond_6

    .line 54
    .line 55
    and-int/lit16 v1, p4, 0x200

    .line 56
    .line 57
    if-nez v1, :cond_4

    .line 58
    .line 59
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    goto :goto_3

    .line 64
    :cond_4
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    :goto_3
    if-eqz v1, :cond_5

    .line 69
    .line 70
    const/16 v1, 0x100

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_5
    const/16 v1, 0x80

    .line 74
    .line 75
    :goto_4
    or-int/2addr v0, v1

    .line 76
    :cond_6
    and-int/lit16 v1, v0, 0x93

    .line 77
    .line 78
    const/16 v2, 0x92

    .line 79
    .line 80
    if-eq v1, v2, :cond_7

    .line 81
    .line 82
    const/4 v1, 0x1

    .line 83
    goto :goto_5

    .line 84
    :cond_7
    const/4 v1, 0x0

    .line 85
    :goto_5
    and-int/lit8 v2, v0, 0x1

    .line 86
    .line 87
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    if-eqz v1, :cond_8

    .line 92
    .line 93
    new-instance v1, Ly61/b;

    .line 94
    .line 95
    invoke-direct {v1, p1, p2}, Ly61/b;-><init>(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;)V

    .line 96
    .line 97
    .line 98
    const v2, 0x7f3f9209

    .line 99
    .line 100
    .line 101
    invoke-static {v2, p3, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    and-int/lit16 v0, v0, 0x380

    .line 106
    .line 107
    or-int/lit8 v0, v0, 0x30

    .line 108
    .line 109
    iget-object v2, p0, Ly61/g;->b:Lh70/o;

    .line 110
    .line 111
    invoke-virtual {p0, v2, v1, p3, v0}, Ly61/g;->f(Lh70/o;Lt2/b;Ll2/o;I)V

    .line 112
    .line 113
    .line 114
    goto :goto_6

    .line 115
    :cond_8
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 116
    .line 117
    .line 118
    :goto_6
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 119
    .line 120
    .line 121
    move-result-object p3

    .line 122
    if-eqz p3, :cond_9

    .line 123
    .line 124
    new-instance v0, Lxk0/g0;

    .line 125
    .line 126
    const/4 v5, 0x5

    .line 127
    move-object v1, p0

    .line 128
    move-object v2, p1

    .line 129
    move-object v3, p2

    .line 130
    move v4, p4

    .line 131
    invoke-direct/range {v0 .. v5}, Lxk0/g0;-><init>(Ljava/lang/Object;Lx2/s;Ljava/lang/Object;II)V

    .line 132
    .line 133
    .line 134
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 135
    .line 136
    :cond_9
    return-void
.end method
