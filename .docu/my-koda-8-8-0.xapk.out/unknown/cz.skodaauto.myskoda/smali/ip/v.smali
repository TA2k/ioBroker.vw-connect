.class public final Lip/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lmw/c;
.implements Ler/h;
.implements Lgs/e;
.implements Lia/c;
.implements Ll/w;
.implements Llp/jg;
.implements Ls21/b;
.implements Lvp/u;
.implements Lxo/a;


# static fields
.field public static e:Lip/v;

.field public static final synthetic f:Lip/v;

.field public static final synthetic g:Lip/v;

.field public static final synthetic h:Lip/v;

.field public static final synthetic i:Lip/v;

.field public static final synthetic j:Lip/v;

.field public static final synthetic k:Lip/v;

.field public static final synthetic l:Lip/v;

.field public static final synthetic m:Lip/v;

.field public static final synthetic n:Lip/v;

.field public static final synthetic o:Lip/v;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lip/v;

    .line 2
    .line 3
    const/16 v1, 0x10

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lip/v;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lip/v;->f:Lip/v;

    .line 9
    .line 10
    new-instance v0, Lip/v;

    .line 11
    .line 12
    const/16 v1, 0x11

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lip/v;-><init>(I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lip/v;->g:Lip/v;

    .line 18
    .line 19
    new-instance v0, Lip/v;

    .line 20
    .line 21
    const/16 v1, 0x12

    .line 22
    .line 23
    invoke-direct {v0, v1}, Lip/v;-><init>(I)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Lip/v;->h:Lip/v;

    .line 27
    .line 28
    new-instance v0, Lip/v;

    .line 29
    .line 30
    const/16 v1, 0x13

    .line 31
    .line 32
    invoke-direct {v0, v1}, Lip/v;-><init>(I)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Lip/v;->i:Lip/v;

    .line 36
    .line 37
    new-instance v0, Lip/v;

    .line 38
    .line 39
    const/16 v1, 0x14

    .line 40
    .line 41
    invoke-direct {v0, v1}, Lip/v;-><init>(I)V

    .line 42
    .line 43
    .line 44
    sput-object v0, Lip/v;->j:Lip/v;

    .line 45
    .line 46
    new-instance v0, Lip/v;

    .line 47
    .line 48
    const/16 v1, 0x15

    .line 49
    .line 50
    invoke-direct {v0, v1}, Lip/v;-><init>(I)V

    .line 51
    .line 52
    .line 53
    sput-object v0, Lip/v;->k:Lip/v;

    .line 54
    .line 55
    new-instance v0, Lip/v;

    .line 56
    .line 57
    const/16 v1, 0x16

    .line 58
    .line 59
    invoke-direct {v0, v1}, Lip/v;-><init>(I)V

    .line 60
    .line 61
    .line 62
    sput-object v0, Lip/v;->l:Lip/v;

    .line 63
    .line 64
    new-instance v0, Lip/v;

    .line 65
    .line 66
    const/16 v1, 0x17

    .line 67
    .line 68
    invoke-direct {v0, v1}, Lip/v;-><init>(I)V

    .line 69
    .line 70
    .line 71
    sput-object v0, Lip/v;->m:Lip/v;

    .line 72
    .line 73
    new-instance v0, Lip/v;

    .line 74
    .line 75
    const/16 v1, 0x18

    .line 76
    .line 77
    invoke-direct {v0, v1}, Lip/v;-><init>(I)V

    .line 78
    .line 79
    .line 80
    sput-object v0, Lip/v;->n:Lip/v;

    .line 81
    .line 82
    new-instance v0, Lip/v;

    .line 83
    .line 84
    const/16 v1, 0x1a

    .line 85
    .line 86
    invoke-direct {v0, v1}, Lip/v;-><init>(I)V

    .line 87
    .line 88
    .line 89
    sput-object v0, Lip/v;->o:Lip/v;

    .line 90
    .line 91
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lip/v;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ler/i;)V
    .locals 0

    const/4 p1, 0x3

    iput p1, p0, Lip/v;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lu/m;Lv/b;Ld01/x;Lj0/h;Lj0/c;)V
    .locals 0

    const/16 p1, 0xe

    iput p1, p0, Lip/v;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    sget-object p0, Landroid/hardware/camera2/CameraCharacteristics;->INFO_SUPPORTED_HARDWARE_LEVEL:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 5
    invoke-virtual {p2, p0}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Integer;

    if-eqz p0, :cond_0

    .line 6
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    move-result p0

    const/4 p1, 0x2

    .line 7
    :cond_0
    new-instance p0, Let/d;

    invoke-direct {p0, p3}, Let/d;-><init>(Ld01/x;)V

    .line 8
    new-instance p0, Lrx/b;

    const/4 p1, 0x5

    invoke-direct {p0, p2, p1}, Lrx/b;-><init>(Ljava/lang/Object;I)V

    invoke-static {p0}, Llp/nf;->b(Lrx/b;)Z

    return-void
.end method

.method public static final b(Lu01/i;[Lu01/i;I)Ljava/lang/String;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    sget-object v2, Lq01/a;->b:Lu01/i;

    .line 6
    .line 7
    invoke-virtual {v0}, Lu01/i;->d()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    const/4 v4, 0x0

    .line 12
    :goto_0
    if-ge v4, v2, :cond_b

    .line 13
    .line 14
    add-int v5, v4, v2

    .line 15
    .line 16
    div-int/lit8 v5, v5, 0x2

    .line 17
    .line 18
    :goto_1
    const/16 v6, 0xa

    .line 19
    .line 20
    const/4 v7, -0x1

    .line 21
    if-le v5, v7, :cond_0

    .line 22
    .line 23
    invoke-virtual {v0, v5}, Lu01/i;->i(I)B

    .line 24
    .line 25
    .line 26
    move-result v8

    .line 27
    if-eq v8, v6, :cond_0

    .line 28
    .line 29
    add-int/lit8 v5, v5, -0x1

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_0
    add-int/lit8 v8, v5, 0x1

    .line 33
    .line 34
    const/4 v9, 0x1

    .line 35
    move v10, v9

    .line 36
    :goto_2
    add-int v11, v8, v10

    .line 37
    .line 38
    invoke-virtual {v0, v11}, Lu01/i;->i(I)B

    .line 39
    .line 40
    .line 41
    move-result v12

    .line 42
    if-eq v12, v6, :cond_1

    .line 43
    .line 44
    add-int/lit8 v10, v10, 0x1

    .line 45
    .line 46
    goto :goto_2

    .line 47
    :cond_1
    sub-int v6, v11, v8

    .line 48
    .line 49
    move/from16 v12, p2

    .line 50
    .line 51
    const/4 v10, 0x0

    .line 52
    const/4 v13, 0x0

    .line 53
    const/4 v14, 0x0

    .line 54
    :goto_3
    if-eqz v10, :cond_2

    .line 55
    .line 56
    const/16 v10, 0x2e

    .line 57
    .line 58
    const/4 v15, 0x0

    .line 59
    goto :goto_4

    .line 60
    :cond_2
    aget-object v15, v1, v12

    .line 61
    .line 62
    invoke-virtual {v15, v13}, Lu01/i;->i(I)B

    .line 63
    .line 64
    .line 65
    move-result v15

    .line 66
    sget-object v16, Le01/e;->a:[B

    .line 67
    .line 68
    and-int/lit16 v15, v15, 0xff

    .line 69
    .line 70
    move/from16 v18, v15

    .line 71
    .line 72
    move v15, v10

    .line 73
    move/from16 v10, v18

    .line 74
    .line 75
    :goto_4
    add-int v3, v8, v14

    .line 76
    .line 77
    invoke-virtual {v0, v3}, Lu01/i;->i(I)B

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    sget-object v17, Le01/e;->a:[B

    .line 82
    .line 83
    and-int/lit16 v3, v3, 0xff

    .line 84
    .line 85
    sub-int/2addr v10, v3

    .line 86
    if-nez v10, :cond_5

    .line 87
    .line 88
    add-int/lit8 v14, v14, 0x1

    .line 89
    .line 90
    add-int/lit8 v13, v13, 0x1

    .line 91
    .line 92
    if-eq v14, v6, :cond_5

    .line 93
    .line 94
    aget-object v3, v1, v12

    .line 95
    .line 96
    invoke-virtual {v3}, Lu01/i;->d()I

    .line 97
    .line 98
    .line 99
    move-result v3

    .line 100
    if-ne v3, v13, :cond_4

    .line 101
    .line 102
    array-length v3, v1

    .line 103
    sub-int/2addr v3, v9

    .line 104
    if-ne v12, v3, :cond_3

    .line 105
    .line 106
    goto :goto_5

    .line 107
    :cond_3
    add-int/lit8 v12, v12, 0x1

    .line 108
    .line 109
    move v13, v7

    .line 110
    move v10, v9

    .line 111
    goto :goto_3

    .line 112
    :cond_4
    move v10, v15

    .line 113
    goto :goto_3

    .line 114
    :cond_5
    :goto_5
    if-gez v10, :cond_6

    .line 115
    .line 116
    :goto_6
    move v2, v5

    .line 117
    goto :goto_0

    .line 118
    :cond_6
    if-lez v10, :cond_7

    .line 119
    .line 120
    :goto_7
    add-int/lit8 v4, v11, 0x1

    .line 121
    .line 122
    goto :goto_0

    .line 123
    :cond_7
    sub-int v3, v6, v14

    .line 124
    .line 125
    aget-object v7, v1, v12

    .line 126
    .line 127
    invoke-virtual {v7}, Lu01/i;->d()I

    .line 128
    .line 129
    .line 130
    move-result v7

    .line 131
    sub-int/2addr v7, v13

    .line 132
    add-int/lit8 v12, v12, 0x1

    .line 133
    .line 134
    array-length v9, v1

    .line 135
    :goto_8
    if-ge v12, v9, :cond_8

    .line 136
    .line 137
    aget-object v10, v1, v12

    .line 138
    .line 139
    invoke-virtual {v10}, Lu01/i;->d()I

    .line 140
    .line 141
    .line 142
    move-result v10

    .line 143
    add-int/2addr v7, v10

    .line 144
    add-int/lit8 v12, v12, 0x1

    .line 145
    .line 146
    goto :goto_8

    .line 147
    :cond_8
    if-ge v7, v3, :cond_9

    .line 148
    .line 149
    goto :goto_6

    .line 150
    :cond_9
    if-le v7, v3, :cond_a

    .line 151
    .line 152
    goto :goto_7

    .line 153
    :cond_a
    add-int/2addr v6, v8

    .line 154
    invoke-virtual {v0, v8, v6}, Lu01/i;->o(II)Lu01/i;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    sget-object v1, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 159
    .line 160
    invoke-virtual {v0, v1}, Lu01/i;->n(Ljava/nio/charset/Charset;)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v0

    .line 164
    return-object v0

    .line 165
    :cond_b
    const/4 v0, 0x0

    .line 166
    return-object v0
.end method

.method public static p(Lb0/z1;)Ld0/d;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Lb0/k1;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    sget-object p0, Ld0/d;->f:Ld0/d;

    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    instance-of v0, p0, Lb0/u0;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    sget-object p0, Ld0/d;->g:Ld0/d;

    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_1
    invoke-static {p0}, Ll0/g;->B(Lb0/z1;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_2

    .line 25
    .line 26
    sget-object p0, Ld0/d;->h:Ld0/d;

    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_2
    instance-of p0, p0, Lt0/e;

    .line 30
    .line 31
    if-eqz p0, :cond_3

    .line 32
    .line 33
    sget-object p0, Ld0/d;->i:Ld0/d;

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_3
    sget-object p0, Ld0/d;->j:Ld0/d;

    .line 37
    .line 38
    return-object p0
.end method


# virtual methods
.method public a()Ljava/lang/Object;
    .locals 1

    .line 1
    new-instance p0, Lgv/a;

    .line 2
    .line 3
    const/4 v0, 0x3

    .line 4
    invoke-direct {p0, v0}, Lgv/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    return-object p0
.end method

.method public c(DLrw/b;)D
    .locals 0

    .line 1
    const-string p0, "extraStore"

    .line 2
    .line 3
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-wide p1
.end method

.method public d(Ll/l;Z)V
    .locals 0

    .line 1
    return-void
.end method

.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 1

    .line 1
    new-instance p0, Lfv/i;

    .line 2
    .line 3
    const-class v0, Landroid/content/Context;

    .line 4
    .line 5
    invoke-virtual {p1, v0}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Landroid/content/Context;

    .line 10
    .line 11
    invoke-direct {p0, p1}, Lfv/i;-><init>(Landroid/content/Context;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public f(Ll/l;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public g(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Llp/tg;

    .line 2
    .line 3
    new-instance p0, Lov/c;

    .line 4
    .line 5
    iget-object v0, p1, Llp/tg;->d:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v1, p1, Llp/tg;->e:Landroid/graphics/Rect;

    .line 8
    .line 9
    iget-object v2, p1, Llp/tg;->f:Ljava/util/List;

    .line 10
    .line 11
    iget-object v3, p1, Llp/tg;->g:Ljava/lang/String;

    .line 12
    .line 13
    invoke-direct {p0, v0, v1, v2, v3}, Lh/w;-><init>(Ljava/lang/String;Landroid/graphics/Rect;Ljava/util/List;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object p1, p1, Llp/tg;->h:Ljava/util/List;

    .line 17
    .line 18
    new-instance v0, Lpy/a;

    .line 19
    .line 20
    const/16 v1, 0xb

    .line 21
    .line 22
    invoke-direct {v0, v1}, Lpy/a;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-static {p1, v0}, Llp/cg;->d(Ljava/util/List;Llp/jg;)Ljava/util/AbstractList;

    .line 26
    .line 27
    .line 28
    return-object p0
.end method

.method public h()Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lip/v;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 7
    .line 8
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 11
    .line 12
    .line 13
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->n0:Lcom/google/android/gms/internal/measurement/n4;

    .line 14
    .line 15
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Ljava/lang/Long;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 22
    .line 23
    .line 24
    move-result-wide v0

    .line 25
    long-to-int p0, v0

    .line 26
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :pswitch_0
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 32
    .line 33
    sget-object p0, Lcom/google/android/gms/internal/measurement/m9;->e:Lcom/google/android/gms/internal/measurement/m9;

    .line 34
    .line 35
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/m9;->d:Lgr/p;

    .line 36
    .line 37
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p0, Lcom/google/android/gms/internal/measurement/n9;

    .line 40
    .line 41
    sget-object p0, Lcom/google/android/gms/internal/measurement/o9;->a:Lcom/google/android/gms/internal/measurement/n4;

    .line 42
    .line 43
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    check-cast p0, Ljava/lang/Boolean;

    .line 48
    .line 49
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    return-object p0

    .line 53
    :pswitch_1
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 54
    .line 55
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 56
    .line 57
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 58
    .line 59
    .line 60
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->C:Lcom/google/android/gms/internal/measurement/n4;

    .line 61
    .line 62
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Ljava/lang/Boolean;

    .line 67
    .line 68
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    return-object p0

    .line 72
    :pswitch_2
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 73
    .line 74
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 75
    .line 76
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 77
    .line 78
    .line 79
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->a0:Lcom/google/android/gms/internal/measurement/n4;

    .line 80
    .line 81
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    check-cast p0, Ljava/lang/String;

    .line 86
    .line 87
    return-object p0

    .line 88
    :pswitch_3
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 89
    .line 90
    sget-object p0, Lcom/google/android/gms/internal/measurement/r8;->e:Lcom/google/android/gms/internal/measurement/r8;

    .line 91
    .line 92
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/r8;->a()Lcom/google/android/gms/internal/measurement/s8;

    .line 93
    .line 94
    .line 95
    sget-object p0, Lcom/google/android/gms/internal/measurement/t8;->d:Lcom/google/android/gms/internal/measurement/n4;

    .line 96
    .line 97
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    check-cast p0, Ljava/lang/Long;

    .line 102
    .line 103
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 104
    .line 105
    .line 106
    move-result-wide v0

    .line 107
    long-to-int p0, v0

    .line 108
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    return-object p0

    .line 113
    :pswitch_4
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 114
    .line 115
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 116
    .line 117
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 118
    .line 119
    .line 120
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->t0:Lcom/google/android/gms/internal/measurement/n4;

    .line 121
    .line 122
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    check-cast p0, Ljava/lang/Long;

    .line 127
    .line 128
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 129
    .line 130
    .line 131
    return-object p0

    .line 132
    :pswitch_5
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 133
    .line 134
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 135
    .line 136
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 137
    .line 138
    .line 139
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->I:Lcom/google/android/gms/internal/measurement/n4;

    .line 140
    .line 141
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    check-cast p0, Ljava/lang/Long;

    .line 146
    .line 147
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 148
    .line 149
    .line 150
    return-object p0

    .line 151
    :pswitch_6
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 152
    .line 153
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 154
    .line 155
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 156
    .line 157
    .line 158
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->M:Lcom/google/android/gms/internal/measurement/n4;

    .line 159
    .line 160
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    check-cast p0, Ljava/lang/String;

    .line 165
    .line 166
    return-object p0

    .line 167
    :pswitch_7
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 168
    .line 169
    sget-object p0, Lcom/google/android/gms/internal/measurement/u8;->e:Lcom/google/android/gms/internal/measurement/u8;

    .line 170
    .line 171
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/u8;->b()Lcom/google/android/gms/internal/measurement/v8;

    .line 172
    .line 173
    .line 174
    sget-object p0, Lcom/google/android/gms/internal/measurement/w8;->c:Lcom/google/android/gms/internal/measurement/n4;

    .line 175
    .line 176
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object p0

    .line 180
    check-cast p0, Ljava/lang/Boolean;

    .line 181
    .line 182
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 183
    .line 184
    .line 185
    return-object p0

    .line 186
    nop

    .line 187
    :pswitch_data_0
    .packed-switch 0x10
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public i(DLrw/b;)D
    .locals 0

    .line 1
    const-string p0, "extraStore"

    .line 2
    .line 3
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-wide p1
.end method

.method public j(DDLrw/b;)D
    .locals 0

    .line 1
    const-string p0, "extraStore"

    .line 2
    .line 3
    invoke-static {p5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-wide/16 p3, 0x0

    .line 7
    .line 8
    cmpl-double p0, p1, p3

    .line 9
    .line 10
    const-wide p3, 0x3feccccccccccccdL    # 0.9

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    if-lez p0, :cond_0

    .line 16
    .line 17
    invoke-static {p1, p2}, Ljava/lang/Math;->log10(D)D

    .line 18
    .line 19
    .line 20
    move-result-wide p0

    .line 21
    mul-double/2addr p0, p3

    .line 22
    const-wide/high16 p2, 0x4024000000000000L    # 10.0

    .line 23
    .line 24
    invoke-static {p2, p3, p0, p1}, Ljava/lang/Math;->pow(DD)D

    .line 25
    .line 26
    .line 27
    move-result-wide p0

    .line 28
    return-wide p0

    .line 29
    :cond_0
    mul-double/2addr p1, p3

    .line 30
    return-wide p1
.end method

.method public k(Ljava/lang/CharSequence;II)Ls21/a;
    .locals 16

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    add-int/lit8 v1, p2, -0x1

    .line 4
    .line 5
    const/4 v3, -0x1

    .line 6
    move v5, v3

    .line 7
    const/4 v4, 0x1

    .line 8
    :goto_0
    const/16 v6, 0x80

    .line 9
    .line 10
    const/16 v7, 0x39

    .line 11
    .line 12
    const/16 v8, 0x30

    .line 13
    .line 14
    const/16 v9, 0x7a

    .line 15
    .line 16
    const/16 v10, 0x61

    .line 17
    .line 18
    const/16 v11, 0x5a

    .line 19
    .line 20
    const/16 v12, 0x41

    .line 21
    .line 22
    const/16 v14, 0x2e

    .line 23
    .line 24
    const/16 v15, 0x2d

    .line 25
    .line 26
    move/from16 v2, p3

    .line 27
    .line 28
    const/16 p0, 0x1

    .line 29
    .line 30
    if-lt v1, v2, :cond_6

    .line 31
    .line 32
    invoke-interface {v0, v1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 33
    .line 34
    .line 35
    move-result v13

    .line 36
    if-lt v13, v12, :cond_0

    .line 37
    .line 38
    if-le v13, v11, :cond_5

    .line 39
    .line 40
    :cond_0
    if-lt v13, v10, :cond_1

    .line 41
    .line 42
    if-gt v13, v9, :cond_1

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    if-lt v13, v8, :cond_2

    .line 46
    .line 47
    if-gt v13, v7, :cond_2

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    if-lt v13, v6, :cond_3

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_3
    const/16 v6, 0x21

    .line 54
    .line 55
    if-eq v13, v6, :cond_5

    .line 56
    .line 57
    if-eq v13, v15, :cond_5

    .line 58
    .line 59
    const/16 v6, 0x2f

    .line 60
    .line 61
    if-eq v13, v6, :cond_5

    .line 62
    .line 63
    const/16 v6, 0x3d

    .line 64
    .line 65
    if-eq v13, v6, :cond_5

    .line 66
    .line 67
    const/16 v6, 0x3f

    .line 68
    .line 69
    if-eq v13, v6, :cond_5

    .line 70
    .line 71
    const/16 v6, 0x2a

    .line 72
    .line 73
    if-eq v13, v6, :cond_5

    .line 74
    .line 75
    const/16 v6, 0x2b

    .line 76
    .line 77
    if-eq v13, v6, :cond_5

    .line 78
    .line 79
    packed-switch v13, :pswitch_data_0

    .line 80
    .line 81
    .line 82
    packed-switch v13, :pswitch_data_1

    .line 83
    .line 84
    .line 85
    packed-switch v13, :pswitch_data_2

    .line 86
    .line 87
    .line 88
    if-ne v13, v14, :cond_6

    .line 89
    .line 90
    if-eqz v4, :cond_4

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_4
    move/from16 v4, p0

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_5
    :goto_1
    :pswitch_0
    move v5, v1

    .line 97
    const/4 v4, 0x0

    .line 98
    :goto_2
    add-int/lit8 v1, v1, -0x1

    .line 99
    .line 100
    goto :goto_0

    .line 101
    :cond_6
    :goto_3
    if-ne v5, v3, :cond_7

    .line 102
    .line 103
    goto/16 :goto_b

    .line 104
    .line 105
    :cond_7
    add-int/lit8 v1, p2, 0x1

    .line 106
    .line 107
    const/4 v4, 0x0

    .line 108
    move/from16 v2, p0

    .line 109
    .line 110
    move v6, v3

    .line 111
    move v13, v6

    .line 112
    :goto_4
    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    .line 113
    .line 114
    .line 115
    move-result v15

    .line 116
    if-ge v1, v15, :cond_15

    .line 117
    .line 118
    invoke-interface {v0, v1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 119
    .line 120
    .line 121
    move-result v15

    .line 122
    if-eqz v2, :cond_c

    .line 123
    .line 124
    if-lt v15, v12, :cond_8

    .line 125
    .line 126
    if-le v15, v11, :cond_b

    .line 127
    .line 128
    :cond_8
    if-lt v15, v10, :cond_9

    .line 129
    .line 130
    if-gt v15, v9, :cond_9

    .line 131
    .line 132
    goto :goto_5

    .line 133
    :cond_9
    if-lt v15, v8, :cond_a

    .line 134
    .line 135
    if-gt v15, v7, :cond_a

    .line 136
    .line 137
    goto :goto_5

    .line 138
    :cond_a
    const/16 v2, 0x80

    .line 139
    .line 140
    if-lt v15, v2, :cond_15

    .line 141
    .line 142
    :cond_b
    :goto_5
    move v15, v1

    .line 143
    move v13, v6

    .line 144
    const/4 v2, 0x0

    .line 145
    const/16 v4, 0x80

    .line 146
    .line 147
    :goto_6
    move/from16 v6, p0

    .line 148
    .line 149
    goto :goto_9

    .line 150
    :cond_c
    if-ne v15, v14, :cond_f

    .line 151
    .line 152
    if-nez v4, :cond_d

    .line 153
    .line 154
    goto :goto_a

    .line 155
    :cond_d
    move/from16 v2, p0

    .line 156
    .line 157
    if-ne v6, v3, :cond_e

    .line 158
    .line 159
    move v6, v4

    .line 160
    move v15, v13

    .line 161
    const/16 v4, 0x80

    .line 162
    .line 163
    move v13, v1

    .line 164
    goto :goto_9

    .line 165
    :cond_e
    move v15, v13

    .line 166
    move v13, v6

    .line 167
    move v6, v4

    .line 168
    const/16 v4, 0x80

    .line 169
    .line 170
    goto :goto_9

    .line 171
    :cond_f
    const/16 v4, 0x2d

    .line 172
    .line 173
    if-ne v15, v4, :cond_10

    .line 174
    .line 175
    move v15, v13

    .line 176
    const/16 v4, 0x80

    .line 177
    .line 178
    move v13, v6

    .line 179
    const/4 v6, 0x0

    .line 180
    goto :goto_9

    .line 181
    :cond_10
    if-lt v15, v12, :cond_11

    .line 182
    .line 183
    if-le v15, v11, :cond_13

    .line 184
    .line 185
    :cond_11
    if-lt v15, v10, :cond_12

    .line 186
    .line 187
    if-gt v15, v9, :cond_12

    .line 188
    .line 189
    goto :goto_7

    .line 190
    :cond_12
    if-lt v15, v8, :cond_14

    .line 191
    .line 192
    if-gt v15, v7, :cond_14

    .line 193
    .line 194
    :cond_13
    :goto_7
    const/16 v4, 0x80

    .line 195
    .line 196
    goto :goto_8

    .line 197
    :cond_14
    const/16 v4, 0x80

    .line 198
    .line 199
    if-lt v15, v4, :cond_15

    .line 200
    .line 201
    :goto_8
    move v15, v1

    .line 202
    move v13, v6

    .line 203
    goto :goto_6

    .line 204
    :goto_9
    add-int/lit8 v1, v1, 0x1

    .line 205
    .line 206
    move v4, v6

    .line 207
    move v6, v13

    .line 208
    move v13, v15

    .line 209
    goto :goto_4

    .line 210
    :cond_15
    :goto_a
    if-eq v6, v3, :cond_16

    .line 211
    .line 212
    if-le v6, v13, :cond_17

    .line 213
    .line 214
    :cond_16
    move v13, v3

    .line 215
    :cond_17
    if-ne v13, v3, :cond_18

    .line 216
    .line 217
    :goto_b
    const/4 v0, 0x0

    .line 218
    return-object v0

    .line 219
    :cond_18
    new-instance v0, Ls21/a;

    .line 220
    .line 221
    sget-object v1, Lr21/c;->e:Lr21/c;

    .line 222
    .line 223
    add-int/lit8 v13, v13, 0x1

    .line 224
    .line 225
    invoke-direct {v0, v1, v5, v13}, Ls21/a;-><init>(Lr21/c;II)V

    .line 226
    .line 227
    .line 228
    return-object v0

    .line 229
    :pswitch_data_0
    .packed-switch 0x23
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch

    .line 230
    .line 231
    .line 232
    .line 233
    .line 234
    .line 235
    .line 236
    .line 237
    .line 238
    .line 239
    .line 240
    .line 241
    .line 242
    .line 243
    :pswitch_data_1
    .packed-switch 0x5e
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch

    .line 244
    .line 245
    .line 246
    .line 247
    .line 248
    .line 249
    .line 250
    .line 251
    .line 252
    .line 253
    :pswitch_data_2
    .packed-switch 0x7b
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public l(DDLrw/b;)D
    .locals 0

    .line 1
    const-string p0, "extraStore"

    .line 2
    .line 3
    invoke-static {p5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-wide/16 p0, 0x0

    .line 7
    .line 8
    cmpl-double p0, p3, p0

    .line 9
    .line 10
    const-wide p1, 0x3ff199999999999aL    # 1.1

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    if-lez p0, :cond_0

    .line 16
    .line 17
    invoke-static {p3, p4}, Ljava/lang/Math;->log10(D)D

    .line 18
    .line 19
    .line 20
    move-result-wide p3

    .line 21
    mul-double/2addr p3, p1

    .line 22
    const-wide/high16 p0, 0x4024000000000000L    # 10.0

    .line 23
    .line 24
    invoke-static {p0, p1, p3, p4}, Ljava/lang/Math;->pow(DD)D

    .line 25
    .line 26
    .line 27
    move-result-wide p0

    .line 28
    return-wide p0

    .line 29
    :cond_0
    mul-double/2addr p3, p1

    .line 30
    return-wide p3
.end method

.method public m()V
    .locals 1

    .line 1
    const-string p0, "DIAGNOSTIC_PROFILE_IS_COMPRESSED"

    .line 2
    .line 3
    const-string v0, "ProfileInstaller"

    .line 4
    .line 5
    invoke-static {v0, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public n(ILjava/lang/Object;)V
    .locals 2

    .line 1
    packed-switch p1, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    :pswitch_0
    const-string p0, ""

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :pswitch_1
    const-string p0, "RESULT_DELETE_SKIP_FILE_SUCCESS"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :pswitch_2
    const-string p0, "RESULT_INSTALL_SKIP_FILE_SUCCESS"

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :pswitch_3
    const-string p0, "RESULT_PARSE_EXCEPTION"

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :pswitch_4
    const-string p0, "RESULT_IO_EXCEPTION"

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :pswitch_5
    const-string p0, "RESULT_BASELINE_PROFILE_NOT_FOUND"

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :pswitch_6
    const-string p0, "RESULT_DESIRED_FORMAT_UNSUPPORTED"

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :pswitch_7
    const-string p0, "RESULT_NOT_WRITABLE"

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :pswitch_8
    const-string p0, "RESULT_UNSUPPORTED_ART_VERSION"

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :pswitch_9
    const-string p0, "RESULT_ALREADY_INSTALLED"

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :pswitch_a
    const-string p0, "RESULT_INSTALL_SUCCESS"

    .line 35
    .line 36
    :goto_0
    const/4 v0, 0x6

    .line 37
    const-string v1, "ProfileInstaller"

    .line 38
    .line 39
    if-eq p1, v0, :cond_0

    .line 40
    .line 41
    const/4 v0, 0x7

    .line 42
    if-eq p1, v0, :cond_0

    .line 43
    .line 44
    const/16 v0, 0x8

    .line 45
    .line 46
    if-eq p1, v0, :cond_0

    .line 47
    .line 48
    invoke-static {v1, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :cond_0
    check-cast p2, Ljava/lang/Throwable;

    .line 53
    .line 54
    invoke-static {v1, p0, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 55
    .line 56
    .line 57
    return-void

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_0
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public synthetic o(Landroid/os/Bundle;)Ljava/lang/Object;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method
