.class public final Lb0/d1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/m1;


# instance fields
.field public d:Z

.field public e:Ljava/lang/Object;

.field public final f:Ljava/lang/Object;

.field public final g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;

.field public final i:Ljava/lang/Object;

.field public j:Ljava/lang/Object;

.field public k:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroid/content/res/AssetManager;Ljava/util/concurrent/Executor;Lia/c;Ljava/lang/String;Ljava/io/File;)V
    .locals 0

    .line 130
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p1, 0x0

    .line 131
    iput-boolean p1, p0, Lb0/d1;->d:Z

    .line 132
    iput-object p2, p0, Lb0/d1;->e:Ljava/lang/Object;

    .line 133
    iput-object p3, p0, Lb0/d1;->f:Ljava/lang/Object;

    .line 134
    iput-object p4, p0, Lb0/d1;->i:Ljava/lang/Object;

    .line 135
    iput-object p5, p0, Lb0/d1;->h:Ljava/lang/Object;

    .line 136
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 p2, 0x1f

    if-lt p1, p2, :cond_0

    .line 137
    sget-object p1, Lia/d;->d:[B

    goto :goto_0

    :cond_0
    const/16 p2, 0x1d

    if-eq p1, p2, :cond_1

    const/16 p2, 0x1e

    if-eq p1, p2, :cond_1

    const/4 p1, 0x0

    goto :goto_0

    .line 138
    :cond_1
    sget-object p1, Lia/d;->e:[B

    .line 139
    :goto_0
    iput-object p1, p0, Lb0/d1;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lg1/u2;La0/j;La50/d;Lt4/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lb0/d1;->e:Ljava/lang/Object;

    .line 3
    iput-object p2, p0, Lb0/d1;->f:Ljava/lang/Object;

    .line 4
    iput-object p3, p0, Lb0/d1;->g:Ljava/lang/Object;

    .line 5
    iput-object p4, p0, Lb0/d1;->h:Ljava/lang/Object;

    const/4 p1, 0x0

    const/4 p2, 0x6

    const p3, 0x7fffffff

    .line 6
    invoke-static {p3, p2, p1}, Llp/jf;->a(IILxy0/a;)Lxy0/j;

    move-result-object p1

    iput-object p1, p0, Lb0/d1;->i:Ljava/lang/Object;

    .line 7
    new-instance p1, Lvp/y1;

    invoke-direct {p1, p2}, Lvp/y1;-><init>(I)V

    iput-object p1, p0, Lb0/d1;->k:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/util/List;Ljava/util/List;)V
    .locals 10

    const-string v0, "effects"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    sget-object v0, Lh0/k;->h:Landroid/util/Range;

    .line 23
    const-string v1, "frameRateRange"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 25
    iput-object p2, p0, Lb0/d1;->e:Ljava/lang/Object;

    .line 26
    iput-object v0, p0, Lb0/d1;->h:Ljava/lang/Object;

    .line 27
    sget-object p2, Lmx0/u;->d:Lmx0/u;

    iput-object p2, p0, Lb0/d1;->i:Ljava/lang/Object;

    .line 28
    sget-object p2, Lmx0/s;->d:Lmx0/s;

    iput-object p2, p0, Lb0/d1;->f:Ljava/lang/Object;

    .line 29
    check-cast p1, Ljava/lang/Iterable;

    invoke-static {p1}, Lmx0/q;->C(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Lb0/d1;->g:Ljava/lang/Object;

    .line 30
    new-instance p2, Lb0/o1;

    const/4 v1, 0x0

    invoke-direct {p2, v1}, Lb0/o1;-><init>(I)V

    iput-object p2, p0, Lb0/d1;->j:Ljava/lang/Object;

    .line 31
    invoke-static {}, Llp/hb;->d()Lj0/c;

    move-result-object p2

    const-string v1, "mainThreadExecutor(...)"

    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p2, p0, Lb0/d1;->k:Ljava/lang/Object;

    .line 32
    invoke-virtual {v0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_0

    goto :goto_1

    .line 33
    :cond_0
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Lb0/z1;

    .line 34
    iget-object p2, p2, Lb0/z1;->e:Ljava/lang/Object;

    .line 35
    sget-object v0, Lh0/o2;->V0:Lh0/g;

    invoke-interface {p2, v0}, Lh0/t1;->j(Lh0/g;)Z

    move-result p2

    if-nez p2, :cond_1

    goto :goto_0

    .line 36
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Can\'t set target frame rate on a UseCase (by Preview.Builder.setTargetFrameRate() or VideoCapture.Builder.setTargetFrameRate()) if the frame rate range has already been set in the SessionConfig."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 37
    :cond_2
    :goto_1
    iget-object p1, p0, Lb0/d1;->f:Ljava/lang/Object;

    check-cast p1, Ljava/util/List;

    iget-object p2, p0, Lb0/d1;->i:Ljava/lang/Object;

    check-cast p2, Ljava/util/Set;

    invoke-interface {p2}, Ljava/util/Set;->isEmpty()Z

    move-result v0

    const/4 v1, 0x1

    if-eqz v0, :cond_3

    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_3

    goto/16 :goto_c

    .line 38
    :cond_3
    check-cast p2, Ljava/lang/Iterable;

    .line 39
    new-instance v0, Ljava/util/ArrayList;

    const/16 v2, 0xa

    invoke-static {p2, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 40
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    .line 41
    check-cast v3, Lc0/a;

    .line 42
    invoke-virtual {v3}, Lc0/a;->a()Le0/b;

    move-result-object v3

    .line 43
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    .line 44
    :cond_4
    invoke-static {v0}, Lmx0/q;->C(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    .line 45
    check-cast v0, Ljava/lang/Iterable;

    .line 46
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_8

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Le0/b;

    .line 47
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 48
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :cond_5
    :goto_4
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_6

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    move-object v6, v5

    check-cast v6, Lc0/a;

    .line 49
    invoke-virtual {v6}, Lc0/a;->a()Le0/b;

    move-result-object v6

    if-ne v6, v2, :cond_5

    .line 50
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_4

    .line 51
    :cond_6
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v2

    if-gt v2, v1, :cond_7

    goto :goto_3

    .line 52
    :cond_7
    new-instance p0, Ljava/lang/StringBuilder;

    const-string p1, "requiredFeatures has conflicting feature values: "

    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    .line 53
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    .line 54
    :cond_8
    move-object v0, p1

    check-cast v0, Ljava/lang/Iterable;

    invoke-static {v0}, Lmx0/q;->C(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v2

    if-ne v0, v2, :cond_28

    .line 55
    check-cast p1, Ljava/lang/Iterable;

    invoke-static {p2, p1}, Lmx0/q;->O(Ljava/lang/Iterable;Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object p1

    .line 56
    invoke-interface {p1}, Ljava/util/Set;->isEmpty()Z

    move-result p2

    if-eqz p2, :cond_27

    .line 57
    iget-object p1, p0, Lb0/d1;->g:Ljava/lang/Object;

    check-cast p1, Ljava/util/List;

    check-cast p1, Ljava/lang/Iterable;

    .line 58
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_9
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_25

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Lb0/z1;

    .line 59
    sget-object v0, Ld0/d;->e:Lip/v;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p2}, Lip/v;->p(Lb0/z1;)Ld0/d;

    move-result-object v0

    sget-object v2, Ld0/d;->j:Ld0/d;

    if-eq v0, v2, :cond_24

    .line 60
    instance-of v0, p2, Lb0/k1;

    if-eqz v0, :cond_a

    const-string v0, "Preview"

    goto :goto_5

    .line 61
    :cond_a
    instance-of v0, p2, Lb0/u0;

    if-eqz v0, :cond_b

    .line 62
    const-string v0, "ImageCapture"

    goto :goto_5

    .line 63
    :cond_b
    instance-of v0, p2, Lb0/i0;

    if-eqz v0, :cond_c

    .line 64
    const-string v0, "ImageAnalysis"

    goto :goto_5

    .line 65
    :cond_c
    invoke-static {p2}, Ll0/g;->B(Lb0/z1;)Z

    move-result v0

    if-eqz v0, :cond_d

    .line 66
    const-string v0, "VideoCapture"

    goto :goto_5

    :cond_d
    const-string v0, "UseCase"

    .line 67
    :goto_5
    iget-object v2, p2, Lb0/z1;->e:Ljava/lang/Object;

    .line 68
    sget-object v3, Le0/b;->i:Lsx0/b;

    .line 69
    invoke-virtual {v3}, Lmx0/e;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_e
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    const/4 v5, 0x2

    const/4 v6, 0x0

    const/4 v7, 0x3

    if-eqz v4, :cond_15

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    move-object v8, v4

    check-cast v8, Le0/b;

    sget-object v9, Ld0/d;->e:Lip/v;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    move-result v8

    if-eqz v8, :cond_14

    if-eq v8, v1, :cond_13

    if-eq v8, v5, :cond_10

    if-ne v8, v7, :cond_f

    .line 71
    sget-object v8, Lh0/y0;->h:Lh0/g;

    invoke-interface {v2, v8}, Lh0/t1;->j(Lh0/g;)Z

    move-result v8

    goto :goto_7

    .line 72
    :cond_f
    new-instance p0, La8/r0;

    .line 73
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 74
    throw p0

    .line 75
    :cond_10
    sget-object v8, Lh0/o2;->a1:Lh0/g;

    invoke-interface {v2, v8}, Lh0/t1;->j(Lh0/g;)Z

    move-result v8

    if-nez v8, :cond_12

    .line 76
    sget-object v8, Lh0/o2;->b1:Lh0/g;

    invoke-interface {v2, v8}, Lh0/t1;->j(Lh0/g;)Z

    move-result v8

    if-eqz v8, :cond_11

    goto :goto_6

    :cond_11
    move v8, v6

    goto :goto_7

    :cond_12
    :goto_6
    move v8, v1

    goto :goto_7

    .line 77
    :cond_13
    sget-object v8, Lh0/o2;->V0:Lh0/g;

    .line 78
    invoke-interface {v2, v8}, Lh0/t1;->j(Lh0/g;)Z

    move-result v8

    goto :goto_7

    .line 79
    :cond_14
    sget-object v8, Lh0/z0;->E0:Lh0/g;

    .line 80
    invoke-interface {v2, v8}, Lh0/t1;->j(Lh0/g;)Z

    move-result v8

    :goto_7
    if-eqz v8, :cond_e

    goto :goto_8

    :cond_15
    const/4 v4, 0x0

    .line 81
    :goto_8
    check-cast v4, Le0/b;

    if-nez v4, :cond_16

    move v6, v1

    :cond_16
    if-nez v6, :cond_9

    .line 82
    new-instance p0, Ljava/lang/StringBuilder;

    const-string p1, "A "

    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    invoke-virtual {v4}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, " value is set to "

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    const-string p1, " despite using feature groups. Do not use APIs like "

    .line 84
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    const-string p1, ".Builder."

    .line 86
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    if-eqz p1, :cond_1b

    if-eq p1, v1, :cond_1a

    if-eq p1, v5, :cond_18

    if-ne p1, v7, :cond_17

    .line 88
    const-string p1, "setOutputFormat"

    goto :goto_9

    .line 89
    :cond_17
    new-instance p0, La8/r0;

    .line 90
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 91
    throw p0

    .line 92
    :cond_18
    invoke-static {p2}, Ll0/g;->B(Lb0/z1;)Z

    move-result p1

    if-eqz p1, :cond_19

    .line 93
    const-string p1, "setVideoStabilizationEnabled"

    goto :goto_9

    .line 94
    :cond_19
    const-string p1, "setPreviewStabilizationEnabled"

    goto :goto_9

    .line 95
    :cond_1a
    const-string p1, "setTargetFrameRateRange"

    goto :goto_9

    .line 96
    :cond_1b
    const-string p1, "setDynamicRange"

    .line 97
    :goto_9
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    const-string p1, " while using feature groups. If "

    .line 99
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    if-eqz p1, :cond_1f

    if-eq p1, v1, :cond_1e

    if-eq p1, v5, :cond_1d

    if-ne p1, v7, :cond_1c

    .line 101
    const-string p1, "JPEG_R output format"

    goto :goto_a

    .line 102
    :cond_1c
    new-instance p0, La8/r0;

    .line 103
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 104
    throw p0

    .line 105
    :cond_1d
    const-string p1, "stabilization"

    goto :goto_a

    .line 106
    :cond_1e
    const-string p1, "60 FPS"

    goto :goto_a

    .line 107
    :cond_1f
    const-string p1, "HDR"

    .line 108
    :goto_a
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 109
    const-string p1, " is required, instead set "

    .line 110
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    if-eqz p1, :cond_23

    if-eq p1, v1, :cond_22

    if-eq p1, v5, :cond_21

    if-eq p1, v7, :cond_20

    new-instance p0, La8/r0;

    .line 112
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 113
    throw p0

    .line 114
    :cond_20
    const-string p1, "GroupableFeature.IMAGE_ULTRA_HDR"

    goto :goto_b

    .line 115
    :cond_21
    const-string p1, "GroupableFeature.PREVIEW_STABILIZATION"

    goto :goto_b

    .line 116
    :cond_22
    const-string p1, "GroupableFeature.FPS_60"

    goto :goto_b

    .line 117
    :cond_23
    const-string p1, "GroupableFeature.HDR_HLG10"

    .line 118
    :goto_b
    const-string p2, " as either a required or preferred feature."

    .line 119
    invoke-static {p0, p1, p2}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    .line 120
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    .line 121
    :cond_24
    new-instance p0, Ljava/lang/StringBuilder;

    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, " is not supported with feature group"

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    .line 122
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    .line 123
    :cond_25
    iget-object p1, p0, Lb0/d1;->e:Ljava/lang/Object;

    check-cast p1, Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result p1

    if-eqz p1, :cond_26

    .line 124
    :goto_c
    iput-boolean v1, p0, Lb0/d1;->d:Z

    return-void

    .line 125
    :cond_26
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Effects aren\'t supported with feature group yet"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 126
    :cond_27
    new-instance p0, Ljava/lang/StringBuilder;

    const-string p2, "requiredFeatures and preferredFeatures have duplicate values: "

    invoke-direct {p0, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    .line 127
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    .line 128
    :cond_28
    new-instance p0, Ljava/lang/StringBuilder;

    const-string p2, "Duplicate values in preferredFeatures("

    invoke-direct {p0, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 p1, 0x29

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    .line 129
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public constructor <init>(Ljava/util/List;Lv/d;Ljava/util/concurrent/Executor;)V
    .locals 4

    const-string v0, "initialCameraIds"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "systemCallbackExecutor"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Lb0/d1;->f:Ljava/lang/Object;

    .line 10
    new-instance v0, Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    iput-object v0, p0, Lb0/d1;->g:Ljava/lang/Object;

    const/4 v0, 0x0

    .line 11
    iput-object v0, p0, Lb0/d1;->h:Ljava/lang/Object;

    const/4 v1, 0x0

    .line 12
    iput-boolean v1, p0, Lb0/d1;->d:Z

    .line 13
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 14
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    .line 15
    const-string v3, "primaryCameraId"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    filled-new-array {v2}, [Ljava/lang/String;

    move-result-object v2

    invoke-static {v2}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v2

    .line 17
    new-instance v3, Lb0/q;

    invoke-direct {v3, v2, v0}, Lb0/q;-><init>(Ljava/util/ArrayList;Lh0/h;)V

    .line 18
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 19
    :cond_0
    iput-object v1, p0, Lb0/d1;->e:Ljava/lang/Object;

    .line 20
    iput-object p2, p0, Lb0/d1;->i:Ljava/lang/Object;

    .line 21
    iput-object p3, p0, Lb0/d1;->j:Ljava/lang/Object;

    return-void
.end method

.method public static final a(Lb0/d1;Lg1/u2;Lg1/r1;FFLrx0/c;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v5, p0

    .line 2
    .line 3
    move-object/from16 v7, p1

    .line 4
    .line 5
    move-object/from16 v0, p2

    .line 6
    .line 7
    move-object/from16 v1, p5

    .line 8
    .line 9
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    instance-of v2, v1, Lg1/s1;

    .line 13
    .line 14
    if-eqz v2, :cond_0

    .line 15
    .line 16
    move-object v2, v1

    .line 17
    check-cast v2, Lg1/s1;

    .line 18
    .line 19
    iget v3, v2, Lg1/s1;->i:I

    .line 20
    .line 21
    const/high16 v4, -0x80000000

    .line 22
    .line 23
    and-int v6, v3, v4

    .line 24
    .line 25
    if-eqz v6, :cond_0

    .line 26
    .line 27
    sub-int/2addr v3, v4

    .line 28
    iput v3, v2, Lg1/s1;->i:I

    .line 29
    .line 30
    :goto_0
    move-object v9, v2

    .line 31
    goto :goto_1

    .line 32
    :cond_0
    new-instance v2, Lg1/s1;

    .line 33
    .line 34
    invoke-direct {v2, v5, v1}, Lg1/s1;-><init>(Lb0/d1;Lrx0/c;)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :goto_1
    iget-object v1, v9, Lg1/s1;->g:Ljava/lang/Object;

    .line 39
    .line 40
    sget-object v10, Lqx0/a;->d:Lqx0/a;

    .line 41
    .line 42
    iget v2, v9, Lg1/s1;->i:I

    .line 43
    .line 44
    const/4 v11, 0x0

    .line 45
    sget-object v12, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    const/4 v13, 0x2

    .line 48
    const/4 v14, 0x1

    .line 49
    if-eqz v2, :cond_3

    .line 50
    .line 51
    if-eq v2, v14, :cond_2

    .line 52
    .line 53
    if-ne v2, v13, :cond_1

    .line 54
    .line 55
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    return-object v12

    .line 59
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 62
    .line 63
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw v0

    .line 67
    :cond_2
    iget v0, v9, Lg1/s1;->f:F

    .line 68
    .line 69
    iget-object v2, v9, Lg1/s1;->e:Lkotlin/jvm/internal/c0;

    .line 70
    .line 71
    iget-object v3, v9, Lg1/s1;->d:Lg1/u2;

    .line 72
    .line 73
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    new-instance v3, Lkotlin/jvm/internal/f0;

    .line 81
    .line 82
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 83
    .line 84
    .line 85
    iput-object v0, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 86
    .line 87
    invoke-virtual {v5, v0}, Lb0/d1;->k(Lg1/r1;)V

    .line 88
    .line 89
    .line 90
    iget-object v0, v5, Lb0/d1;->i:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast v0, Lxy0/j;

    .line 93
    .line 94
    invoke-static {v0}, Lb0/d1;->j(Lxy0/j;)Lg1/r1;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    if-eqz v0, :cond_4

    .line 99
    .line 100
    invoke-virtual {v5, v0}, Lb0/d1;->k(Lg1/r1;)V

    .line 101
    .line 102
    .line 103
    iget-object v1, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v1, Lg1/r1;

    .line 106
    .line 107
    invoke-virtual {v1, v0}, Lg1/r1;->a(Lg1/r1;)Lg1/r1;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    iput-object v0, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 112
    .line 113
    :cond_4
    new-instance v1, Lkotlin/jvm/internal/c0;

    .line 114
    .line 115
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 116
    .line 117
    .line 118
    iget-object v0, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast v0, Lg1/r1;

    .line 121
    .line 122
    iget-wide v13, v0, Lg1/r1;->a:J

    .line 123
    .line 124
    invoke-virtual {v7, v13, v14}, Lg1/u2;->e(J)J

    .line 125
    .line 126
    .line 127
    move-result-wide v13

    .line 128
    invoke-virtual {v7, v13, v14}, Lg1/u2;->g(J)F

    .line 129
    .line 130
    .line 131
    move-result v0

    .line 132
    iput v0, v1, Lkotlin/jvm/internal/c0;->d:F

    .line 133
    .line 134
    invoke-static {v0}, Lg1/q1;->a(F)Z

    .line 135
    .line 136
    .line 137
    move-result v0

    .line 138
    if-eqz v0, :cond_5

    .line 139
    .line 140
    goto/16 :goto_6

    .line 141
    .line 142
    :cond_5
    new-instance v2, Lkotlin/jvm/internal/f0;

    .line 143
    .line 144
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 145
    .line 146
    .line 147
    const/16 v0, 0x1e

    .line 148
    .line 149
    invoke-static {v11, v11, v0}, Lc1/d;->b(FFI)Lc1/k;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    iput-object v0, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 154
    .line 155
    new-instance v0, Lg1/t1;

    .line 156
    .line 157
    const/4 v8, 0x0

    .line 158
    move/from16 v4, p3

    .line 159
    .line 160
    move/from16 v6, p4

    .line 161
    .line 162
    invoke-direct/range {v0 .. v8}, Lg1/t1;-><init>(Lkotlin/jvm/internal/c0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;FLb0/d1;FLg1/u2;Lkotlin/coroutines/Continuation;)V

    .line 163
    .line 164
    .line 165
    iput-object v7, v9, Lg1/s1;->d:Lg1/u2;

    .line 166
    .line 167
    iput-object v1, v9, Lg1/s1;->e:Lkotlin/jvm/internal/c0;

    .line 168
    .line 169
    iput v6, v9, Lg1/s1;->f:F

    .line 170
    .line 171
    const/4 v15, 0x1

    .line 172
    iput v15, v9, Lg1/s1;->i:I

    .line 173
    .line 174
    invoke-virtual {v5, v7, v0, v9}, Lb0/d1;->n(Lg1/u2;Lg1/t1;Lrx0/c;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v0

    .line 178
    if-ne v0, v10, :cond_6

    .line 179
    .line 180
    goto/16 :goto_5

    .line 181
    .line 182
    :cond_6
    move-object v2, v1

    .line 183
    move v0, v6

    .line 184
    move-object v3, v7

    .line 185
    :goto_2
    iget-object v1, v5, Lb0/d1;->k:Ljava/lang/Object;

    .line 186
    .line 187
    check-cast v1, Lvp/y1;

    .line 188
    .line 189
    iget-object v4, v1, Lvp/y1;->e:Ljava/lang/Object;

    .line 190
    .line 191
    check-cast v4, Lq3/d;

    .line 192
    .line 193
    const v6, 0x7f7fffff    # Float.MAX_VALUE

    .line 194
    .line 195
    .line 196
    invoke-virtual {v4, v6}, Lq3/d;->b(F)F

    .line 197
    .line 198
    .line 199
    move-result v4

    .line 200
    iget-object v1, v1, Lvp/y1;->f:Ljava/lang/Object;

    .line 201
    .line 202
    check-cast v1, Lq3/d;

    .line 203
    .line 204
    invoke-virtual {v1, v6}, Lq3/d;->b(F)F

    .line 205
    .line 206
    .line 207
    move-result v1

    .line 208
    invoke-static {v4, v1}, Lkp/g9;->a(FF)J

    .line 209
    .line 210
    .line 211
    move-result-wide v6

    .line 212
    const-wide/16 v13, 0x0

    .line 213
    .line 214
    cmp-long v1, v6, v13

    .line 215
    .line 216
    if-nez v1, :cond_9

    .line 217
    .line 218
    iget v1, v2, Lkotlin/jvm/internal/c0;->d:F

    .line 219
    .line 220
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 221
    .line 222
    .line 223
    move-result v1

    .line 224
    const/16 v4, 0x64

    .line 225
    .line 226
    int-to-float v4, v4

    .line 227
    div-float/2addr v1, v4

    .line 228
    invoke-static {v1, v0}, Ljava/lang/Math;->min(FF)F

    .line 229
    .line 230
    .line 231
    move-result v0

    .line 232
    iget v1, v2, Lkotlin/jvm/internal/c0;->d:F

    .line 233
    .line 234
    invoke-static {v1}, Ljava/lang/Math;->signum(F)F

    .line 235
    .line 236
    .line 237
    move-result v1

    .line 238
    invoke-virtual {v3, v1}, Lg1/u2;->d(F)F

    .line 239
    .line 240
    .line 241
    move-result v1

    .line 242
    mul-float/2addr v1, v0

    .line 243
    const/16 v0, 0x3e8

    .line 244
    .line 245
    int-to-float v0, v0

    .line 246
    mul-float/2addr v1, v0

    .line 247
    cmpg-float v0, v1, v11

    .line 248
    .line 249
    if-nez v0, :cond_7

    .line 250
    .line 251
    move-wide v6, v13

    .line 252
    goto :goto_4

    .line 253
    :cond_7
    iget-object v0, v3, Lg1/u2;->d:Lg1/w1;

    .line 254
    .line 255
    sget-object v2, Lg1/w1;->e:Lg1/w1;

    .line 256
    .line 257
    if-ne v0, v2, :cond_8

    .line 258
    .line 259
    invoke-static {v1, v11}, Lkp/g9;->a(FF)J

    .line 260
    .line 261
    .line 262
    move-result-wide v0

    .line 263
    :goto_3
    move-wide v6, v0

    .line 264
    goto :goto_4

    .line 265
    :cond_8
    invoke-static {v11, v1}, Lkp/g9;->a(FF)J

    .line 266
    .line 267
    .line 268
    move-result-wide v0

    .line 269
    goto :goto_3

    .line 270
    :cond_9
    :goto_4
    iget-object v0, v5, Lb0/d1;->g:Ljava/lang/Object;

    .line 271
    .line 272
    check-cast v0, La50/d;

    .line 273
    .line 274
    new-instance v1, Lt4/q;

    .line 275
    .line 276
    invoke-direct {v1, v6, v7}, Lt4/q;-><init>(J)V

    .line 277
    .line 278
    .line 279
    const/4 v2, 0x0

    .line 280
    iput-object v2, v9, Lg1/s1;->d:Lg1/u2;

    .line 281
    .line 282
    iput-object v2, v9, Lg1/s1;->e:Lkotlin/jvm/internal/c0;

    .line 283
    .line 284
    const/4 v2, 0x2

    .line 285
    iput v2, v9, Lg1/s1;->i:I

    .line 286
    .line 287
    invoke-virtual {v0, v1, v9}, La50/d;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    if-ne v12, v10, :cond_a

    .line 291
    .line 292
    :goto_5
    return-object v10

    .line 293
    :cond_a
    :goto_6
    return-object v12
.end method

.method public static final b(Lb0/d1;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/c0;Lg1/u2;Lkotlin/jvm/internal/f0;JLrx0/c;)Ljava/lang/Object;
    .locals 14

    .line 1
    move-wide/from16 v0, p5

    .line 2
    .line 3
    move-object/from16 v2, p7

    .line 4
    .line 5
    instance-of v3, v2, Lg1/u1;

    .line 6
    .line 7
    if-eqz v3, :cond_0

    .line 8
    .line 9
    move-object v3, v2

    .line 10
    check-cast v3, Lg1/u1;

    .line 11
    .line 12
    iget v4, v3, Lg1/u1;->j:I

    .line 13
    .line 14
    const/high16 v5, -0x80000000

    .line 15
    .line 16
    and-int v6, v4, v5

    .line 17
    .line 18
    if-eqz v6, :cond_0

    .line 19
    .line 20
    sub-int/2addr v4, v5

    .line 21
    iput v4, v3, Lg1/u1;->j:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v3, Lg1/u1;

    .line 25
    .line 26
    invoke-direct {v3, v2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v2, v3, Lg1/u1;->i:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v5, v3, Lg1/u1;->j:I

    .line 34
    .line 35
    const/4 v6, 0x1

    .line 36
    if-eqz v5, :cond_2

    .line 37
    .line 38
    if-ne v5, v6, :cond_1

    .line 39
    .line 40
    iget-object p0, v3, Lg1/u1;->h:Lkotlin/jvm/internal/f0;

    .line 41
    .line 42
    iget-object v0, v3, Lg1/u1;->g:Lg1/u2;

    .line 43
    .line 44
    iget-object v1, v3, Lg1/u1;->f:Lkotlin/jvm/internal/c0;

    .line 45
    .line 46
    iget-object v4, v3, Lg1/u1;->e:Lkotlin/jvm/internal/f0;

    .line 47
    .line 48
    iget-object v3, v3, Lg1/u1;->d:Lb0/d1;

    .line 49
    .line 50
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    move-object v9, p0

    .line 54
    move-object v8, v0

    .line 55
    move-object p0, v3

    .line 56
    goto :goto_1

    .line 57
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_2
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    const-wide/16 v7, 0x0

    .line 69
    .line 70
    cmp-long v2, v0, v7

    .line 71
    .line 72
    if-gez v2, :cond_3

    .line 73
    .line 74
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 75
    .line 76
    return-object p0

    .line 77
    :cond_3
    new-instance v2, Ldm0/h;

    .line 78
    .line 79
    const/4 v5, 0x0

    .line 80
    const/16 v7, 0x14

    .line 81
    .line 82
    invoke-direct {v2, p0, v5, v7}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 83
    .line 84
    .line 85
    iput-object p0, v3, Lg1/u1;->d:Lb0/d1;

    .line 86
    .line 87
    iput-object p1, v3, Lg1/u1;->e:Lkotlin/jvm/internal/f0;

    .line 88
    .line 89
    move-object/from16 v7, p2

    .line 90
    .line 91
    iput-object v7, v3, Lg1/u1;->f:Lkotlin/jvm/internal/c0;

    .line 92
    .line 93
    move-object/from16 v8, p3

    .line 94
    .line 95
    iput-object v8, v3, Lg1/u1;->g:Lg1/u2;

    .line 96
    .line 97
    move-object/from16 v9, p4

    .line 98
    .line 99
    iput-object v9, v3, Lg1/u1;->h:Lkotlin/jvm/internal/f0;

    .line 100
    .line 101
    iput v6, v3, Lg1/u1;->j:I

    .line 102
    .line 103
    invoke-static {v0, v1, v2, v3}, Lvy0/e0;->T(JLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v2

    .line 107
    if-ne v2, v4, :cond_4

    .line 108
    .line 109
    return-object v4

    .line 110
    :cond_4
    move-object v4, p1

    .line 111
    move-object v1, v7

    .line 112
    :goto_1
    check-cast v2, Lg1/r1;

    .line 113
    .line 114
    if-eqz v2, :cond_5

    .line 115
    .line 116
    iget-object v0, v4, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast v0, Lg1/r1;

    .line 119
    .line 120
    iget-boolean v0, v0, Lg1/r1;->c:Z

    .line 121
    .line 122
    iget-wide v10, v2, Lg1/r1;->a:J

    .line 123
    .line 124
    iget-wide v12, v2, Lg1/r1;->b:J

    .line 125
    .line 126
    new-instance v3, Lg1/r1;

    .line 127
    .line 128
    move/from16 p6, v0

    .line 129
    .line 130
    move-object p1, v3

    .line 131
    move-wide/from16 p2, v10

    .line 132
    .line 133
    move-wide/from16 p4, v12

    .line 134
    .line 135
    invoke-direct/range {p1 .. p6}, Lg1/r1;-><init>(JJZ)V

    .line 136
    .line 137
    .line 138
    move-object v0, p1

    .line 139
    iput-object v0, v4, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 140
    .line 141
    invoke-virtual {v8, v10, v11}, Lg1/u2;->e(J)J

    .line 142
    .line 143
    .line 144
    move-result-wide v3

    .line 145
    invoke-virtual {v8, v3, v4}, Lg1/u2;->g(J)F

    .line 146
    .line 147
    .line 148
    move-result v0

    .line 149
    iput v0, v1, Lkotlin/jvm/internal/c0;->d:F

    .line 150
    .line 151
    const/16 v0, 0x1e

    .line 152
    .line 153
    const/4 v3, 0x0

    .line 154
    invoke-static {v3, v3, v0}, Lc1/d;->b(FFI)Lc1/k;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    iput-object v0, v9, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 159
    .line 160
    invoke-virtual {p0, v2}, Lb0/d1;->k(Lg1/r1;)V

    .line 161
    .line 162
    .line 163
    iget p0, v1, Lkotlin/jvm/internal/c0;->d:F

    .line 164
    .line 165
    invoke-static {p0}, Lg1/q1;->a(F)Z

    .line 166
    .line 167
    .line 168
    move-result p0

    .line 169
    xor-int/2addr p0, v6

    .line 170
    goto :goto_2

    .line 171
    :cond_5
    const/4 p0, 0x0

    .line 172
    :goto_2
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    return-object p0
.end method

.method public static j(Lxy0/j;)Lg1/r1;
    .locals 3

    .line 1
    new-instance v0, Ld2/g;

    .line 2
    .line 3
    const/16 v1, 0x10

    .line 4
    .line 5
    invoke-direct {v0, p0, v1}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 6
    .line 7
    .line 8
    new-instance p0, Lg1/l1;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    const/4 v2, 0x0

    .line 12
    invoke-direct {p0, v0, v2, v1}, Lg1/l1;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 13
    .line 14
    .line 15
    invoke-static {p0}, Llp/ke;->a(Lay0/n;)Lky0/k;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    :goto_0
    invoke-virtual {p0}, Lky0/k;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    invoke-virtual {p0}, Lky0/k;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    check-cast v0, Lg1/r1;

    .line 30
    .line 31
    if-nez v2, :cond_0

    .line 32
    .line 33
    :goto_1
    move-object v2, v0

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-virtual {v2, v0}, Lg1/r1;->a(Lg1/r1;)Lg1/r1;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    return-object v2
.end method


# virtual methods
.method public c(Lg1/t2;F)F
    .locals 3

    .line 1
    iget-object p0, p0, Lb0/d1;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lg1/u2;

    .line 4
    .line 5
    invoke-virtual {p0, p2}, Lg1/u2;->d(F)F

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    invoke-virtual {p0, p2}, Lg1/u2;->h(F)J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    iget-object p1, p1, Lg1/t2;->a:Lg1/u2;

    .line 14
    .line 15
    iget-object p2, p1, Lg1/u2;->k:Lg1/e2;

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    invoke-virtual {p1, p2, v0, v1, v2}, Lg1/u2;->c(Lg1/e2;JI)J

    .line 19
    .line 20
    .line 21
    move-result-wide p1

    .line 22
    invoke-virtual {p0, p1, p2}, Lg1/u2;->e(J)J

    .line 23
    .line 24
    .line 25
    move-result-wide p1

    .line 26
    invoke-virtual {p0, p1, p2}, Lg1/u2;->g(J)F

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    return p0
.end method

.method public d()Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 2

    .line 1
    new-instance v0, Lrx/b;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, p0, v1}, Lrx/b;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    invoke-static {v0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public e(Landroid/content/res/AssetManager;Ljava/lang/String;)Ljava/io/FileInputStream;
    .locals 0

    .line 1
    :try_start_0
    invoke-virtual {p1, p2}, Landroid/content/res/AssetManager;->openFd(Ljava/lang/String;)Landroid/content/res/AssetFileDescriptor;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-virtual {p1}, Landroid/content/res/AssetFileDescriptor;->createInputStream()Ljava/io/FileInputStream;

    .line 6
    .line 7
    .line 8
    move-result-object p0
    :try_end_0
    .catch Ljava/io/FileNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    return-object p0

    .line 10
    :catch_0
    move-exception p1

    .line 11
    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    const-string p2, "compressed"

    .line 18
    .line 19
    invoke-virtual {p1, p2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    iget-object p0, p0, Lb0/d1;->f:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Lia/c;

    .line 28
    .line 29
    invoke-interface {p0}, Lia/c;->m()V

    .line 30
    .line 31
    .line 32
    :cond_0
    const/4 p0, 0x0

    .line 33
    return-object p0
.end method

.method public f(Lh0/l1;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lb0/d1;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Lh0/a;

    .line 20
    .line 21
    iget-object v2, v1, Lh0/a;->b:Lh0/l1;

    .line 22
    .line 23
    invoke-virtual {v2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    const/4 v1, 0x0

    .line 31
    :goto_0
    if-eqz v1, :cond_2

    .line 32
    .line 33
    iget-object p1, p0, Lb0/d1;->g:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p1, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 36
    .line 37
    invoke-virtual {p1, v1}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    :cond_2
    iget-object p1, p0, Lb0/d1;->f:Ljava/lang/Object;

    .line 41
    .line 42
    monitor-enter p1

    .line 43
    :try_start_0
    iget-boolean v0, p0, Lb0/d1;->d:Z

    .line 44
    .line 45
    if-eqz v0, :cond_3

    .line 46
    .line 47
    iget-object v0, p0, Lb0/d1;->g:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;->isEmpty()Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-eqz v0, :cond_3

    .line 56
    .line 57
    const-string v0, "CameraPresenceSrc"

    .line 58
    .line 59
    const-string v1, "Last observer removed. Stopping monitoring."

    .line 60
    .line 61
    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 62
    .line 63
    .line 64
    const/4 v0, 0x0

    .line 65
    iput-boolean v0, p0, Lb0/d1;->d:Z

    .line 66
    .line 67
    invoke-virtual {p0}, Lb0/d1;->i()V

    .line 68
    .line 69
    .line 70
    goto :goto_1

    .line 71
    :catchall_0
    move-exception p0

    .line 72
    goto :goto_2

    .line 73
    :cond_3
    :goto_1
    monitor-exit p1

    .line 74
    return-void

    .line 75
    :goto_2
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 76
    throw p0
.end method

.method public g(ILjava/io/Serializable;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lb0/d1;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/concurrent/Executor;

    .line 4
    .line 5
    new-instance v1, Lb/p;

    .line 6
    .line 7
    const/4 v2, 0x3

    .line 8
    invoke-direct {v1, p1, v2, p0, p2}, Lb/p;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public h()V
    .locals 3

    .line 1
    iget-object v0, p0, Lb0/d1;->k:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lu/e0;

    .line 4
    .line 5
    const-string v1, "Camera2PresenceSrc"

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const-string v0, "Monitoring already started. Unregistering existing callback."

    .line 10
    .line 11
    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Lb0/d1;->i()V

    .line 15
    .line 16
    .line 17
    :cond_0
    const-string v0, "Starting system availability monitoring."

    .line 18
    .line 19
    invoke-static {v1, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 20
    .line 21
    .line 22
    new-instance v0, Lu/e0;

    .line 23
    .line 24
    invoke-direct {v0, p0}, Lu/e0;-><init>(Lb0/d1;)V

    .line 25
    .line 26
    .line 27
    iput-object v0, p0, Lb0/d1;->k:Ljava/lang/Object;

    .line 28
    .line 29
    iget-object v1, p0, Lb0/d1;->i:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v1, Lv/d;

    .line 32
    .line 33
    iget-object v2, p0, Lb0/d1;->j:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v2, Ljava/util/concurrent/Executor;

    .line 36
    .line 37
    iget-object v1, v1, Lv/d;->a:Lv/e;

    .line 38
    .line 39
    iget-object v1, v1, Lh/w;->b:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v1, Landroid/hardware/camera2/CameraManager;

    .line 42
    .line 43
    invoke-virtual {v1, v2, v0}, Landroid/hardware/camera2/CameraManager;->registerAvailabilityCallback(Ljava/util/concurrent/Executor;Landroid/hardware/camera2/CameraManager$AvailabilityCallback;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0}, Lb0/d1;->d()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    new-instance v0, Lk0/e;

    .line 51
    .line 52
    const/4 v1, 0x1

    .line 53
    invoke-direct {v0, p0, v1}, Lk0/e;-><init>(Lcom/google/common/util/concurrent/ListenableFuture;I)V

    .line 54
    .line 55
    .line 56
    invoke-static {v0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 57
    .line 58
    .line 59
    return-void
.end method

.method public i()V
    .locals 4

    .line 1
    const-string v0, "Stopping system availability monitoring."

    .line 2
    .line 3
    const-string v1, "Camera2PresenceSrc"

    .line 4
    .line 5
    invoke-static {v1, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lb0/d1;->k:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lu/e0;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    :try_start_0
    iget-object v3, p0, Lb0/d1;->i:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v3, Lv/d;

    .line 18
    .line 19
    iget-object v3, v3, Lv/d;->a:Lv/e;

    .line 20
    .line 21
    iget-object v3, v3, Lh/w;->b:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v3, Landroid/hardware/camera2/CameraManager;

    .line 24
    .line 25
    invoke-virtual {v3, v0}, Landroid/hardware/camera2/CameraManager;->unregisterAvailabilityCallback(Landroid/hardware/camera2/CameraManager$AvailabilityCallback;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    .line 27
    .line 28
    iput-object v2, p0, Lb0/d1;->k:Ljava/lang/Object;

    .line 29
    .line 30
    return-void

    .line 31
    :catch_0
    move-exception v0

    .line 32
    :try_start_1
    const-string v3, "Failed to unregister system availability callback."

    .line 33
    .line 34
    invoke-static {v1, v3, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 35
    .line 36
    .line 37
    iput-object v2, p0, Lb0/d1;->k:Ljava/lang/Object;

    .line 38
    .line 39
    return-void

    .line 40
    :catchall_0
    move-exception v0

    .line 41
    iput-object v2, p0, Lb0/d1;->k:Ljava/lang/Object;

    .line 42
    .line 43
    throw v0

    .line 44
    :cond_0
    return-void
.end method

.method public k(Lg1/r1;)V
    .locals 6

    .line 1
    iget-object p0, p0, Lb0/d1;->k:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/y1;

    .line 4
    .line 5
    iget-wide v0, p1, Lg1/r1;->b:J

    .line 6
    .line 7
    iget-wide v2, p1, Lg1/r1;->a:J

    .line 8
    .line 9
    iget-object p1, p0, Lvp/y1;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p1, Lq3/d;

    .line 12
    .line 13
    const/16 v4, 0x20

    .line 14
    .line 15
    shr-long v4, v2, v4

    .line 16
    .line 17
    long-to-int v4, v4

    .line 18
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 19
    .line 20
    .line 21
    move-result v4

    .line 22
    invoke-virtual {p1, v0, v1, v4}, Lq3/d;->a(JF)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lvp/y1;->f:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Lq3/d;

    .line 28
    .line 29
    const-wide v4, 0xffffffffL

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    and-long/2addr v2, v4

    .line 35
    long-to-int p1, v2

    .line 36
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 37
    .line 38
    .line 39
    move-result p1

    .line 40
    invoke-virtual {p0, v0, v1, p1}, Lq3/d;->a(JF)V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public l(Ljava/util/ArrayList;Lb0/s;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lb0/d1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    const/4 v1, 0x1

    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz p2, :cond_2

    .line 7
    .line 8
    :try_start_0
    iget-object p1, p0, Lb0/d1;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p1, Ljava/lang/Throwable;

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    iget-object p1, p0, Lb0/d1;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p1, Ljava/util/List;

    .line 17
    .line 18
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    if-nez p1, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    move p1, v2

    .line 26
    goto :goto_1

    .line 27
    :catchall_0
    move-exception p0

    .line 28
    goto/16 :goto_7

    .line 29
    .line 30
    :cond_1
    :goto_0
    move p1, v1

    .line 31
    :goto_1
    iput-object p2, p0, Lb0/d1;->h:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object p2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 34
    .line 35
    iput-object p2, p0, Lb0/d1;->e:Ljava/lang/Object;

    .line 36
    .line 37
    goto :goto_4

    .line 38
    :cond_2
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    iget-object p2, p0, Lb0/d1;->h:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p2, Ljava/lang/Throwable;

    .line 44
    .line 45
    if-nez p2, :cond_4

    .line 46
    .line 47
    iget-object p2, p0, Lb0/d1;->e:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p2, Ljava/util/List;

    .line 50
    .line 51
    invoke-interface {p2, p1}, Ljava/util/List;->equals(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result p2

    .line 55
    if-nez p2, :cond_3

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_3
    move p2, v2

    .line 59
    goto :goto_3

    .line 60
    :cond_4
    :goto_2
    move p2, v1

    .line 61
    :goto_3
    const/4 v3, 0x0

    .line 62
    iput-object v3, p0, Lb0/d1;->h:Ljava/lang/Object;

    .line 63
    .line 64
    iput-object p1, p0, Lb0/d1;->e:Ljava/lang/Object;

    .line 65
    .line 66
    move p1, p2

    .line 67
    :goto_4
    iget-object p2, p0, Lb0/d1;->e:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast p2, Ljava/util/List;

    .line 70
    .line 71
    invoke-static {p2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 72
    .line 73
    .line 74
    move-result-object p2

    .line 75
    iget-object v3, p0, Lb0/d1;->h:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v3, Ljava/lang/Throwable;

    .line 78
    .line 79
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 80
    if-eqz p1, :cond_6

    .line 81
    .line 82
    const-string p1, "CameraPresenceSrc"

    .line 83
    .line 84
    new-instance v0, Ljava/lang/StringBuilder;

    .line 85
    .line 86
    const-string v4, "Data changed. Notifying "

    .line 87
    .line 88
    invoke-direct {v0, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    iget-object v4, p0, Lb0/d1;->g:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast v4, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 94
    .line 95
    invoke-virtual {v4}, Ljava/util/concurrent/CopyOnWriteArrayList;->size()I

    .line 96
    .line 97
    .line 98
    move-result v4

    .line 99
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    const-string v4, " observers. Error: "

    .line 103
    .line 104
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    if-eqz v3, :cond_5

    .line 108
    .line 109
    goto :goto_5

    .line 110
    :cond_5
    move v1, v2

    .line 111
    :goto_5
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    invoke-static {p1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 119
    .line 120
    .line 121
    iget-object p0, p0, Lb0/d1;->g:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 124
    .line 125
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    :goto_6
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 130
    .line 131
    .line 132
    move-result p1

    .line 133
    if-eqz p1, :cond_6

    .line 134
    .line 135
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    check-cast p1, Lh0/a;

    .line 140
    .line 141
    iget-object v0, p1, Lh0/a;->a:Ljava/util/concurrent/Executor;

    .line 142
    .line 143
    new-instance v1, La8/y0;

    .line 144
    .line 145
    const/16 v2, 0x9

    .line 146
    .line 147
    invoke-direct {v1, v3, p1, p2, v2}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 148
    .line 149
    .line 150
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 151
    .line 152
    .line 153
    goto :goto_6

    .line 154
    :cond_6
    return-void

    .line 155
    :goto_7
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 156
    throw p0
.end method

.method public m(Ljava/util/concurrent/Executor;Lh0/l1;)V
    .locals 3

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lb0/d1;->g:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 7
    .line 8
    new-instance v1, Lh0/a;

    .line 9
    .line 10
    invoke-direct {v1, p1, p2}, Lh0/a;-><init>(Ljava/util/concurrent/Executor;Lh0/l1;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lb0/d1;->f:Ljava/lang/Object;

    .line 17
    .line 18
    monitor-enter v0

    .line 19
    :try_start_0
    iget-boolean v1, p0, Lb0/d1;->d:Z

    .line 20
    .line 21
    if-nez v1, :cond_0

    .line 22
    .line 23
    iget-object v1, p0, Lb0/d1;->g:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v1, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 26
    .line 27
    invoke-virtual {v1}, Ljava/util/concurrent/CopyOnWriteArrayList;->isEmpty()Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-nez v1, :cond_0

    .line 32
    .line 33
    const-string v1, "CameraPresenceSrc"

    .line 34
    .line 35
    const-string v2, "First observer added. Starting monitoring."

    .line 36
    .line 37
    invoke-static {v1, v2}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 38
    .line 39
    .line 40
    const/4 v1, 0x1

    .line 41
    iput-boolean v1, p0, Lb0/d1;->d:Z

    .line 42
    .line 43
    invoke-virtual {p0}, Lb0/d1;->h()V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :catchall_0
    move-exception p0

    .line 48
    goto :goto_1

    .line 49
    :cond_0
    :goto_0
    iget-object v1, p0, Lb0/d1;->e:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v1, Ljava/util/List;

    .line 52
    .line 53
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    iget-object p0, p0, Lb0/d1;->h:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p0, Ljava/lang/Throwable;

    .line 60
    .line 61
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 62
    new-instance v0, Lh0/a;

    .line 63
    .line 64
    invoke-direct {v0, p1, p2}, Lh0/a;-><init>(Ljava/util/concurrent/Executor;Lh0/l1;)V

    .line 65
    .line 66
    .line 67
    new-instance p2, La8/y0;

    .line 68
    .line 69
    const/16 v2, 0x9

    .line 70
    .line 71
    invoke-direct {p2, p0, v0, v1, v2}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 72
    .line 73
    .line 74
    invoke-interface {p1, p2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 75
    .line 76
    .line 77
    return-void

    .line 78
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 79
    throw p0
.end method

.method public n(Lg1/u2;Lg1/t1;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p3, Lg1/v1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lg1/v1;

    .line 7
    .line 8
    iget v1, v0, Lg1/v1;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lg1/v1;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/v1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lg1/v1;-><init>(Lb0/d1;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lg1/v1;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/v1;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iput-boolean v3, p0, Lb0/d1;->d:Z

    .line 52
    .line 53
    new-instance p3, Le60/m;

    .line 54
    .line 55
    const/4 v2, 0x0

    .line 56
    const/16 v4, 0x12

    .line 57
    .line 58
    invoke-direct {p3, v4, p1, p2, v2}, Le60/m;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 59
    .line 60
    .line 61
    iput v3, v0, Lg1/v1;->f:I

    .line 62
    .line 63
    new-instance p1, Lvy0/y1;

    .line 64
    .line 65
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    const/4 v2, 0x0

    .line 70
    invoke-direct {p1, p2, v0, v2}, Lvy0/y1;-><init>(Lpx0/g;Lkotlin/coroutines/Continuation;I)V

    .line 71
    .line 72
    .line 73
    invoke-static {p1, v3, p1, p3}, Ljp/rb;->a(Laz0/p;ZLaz0/p;Lay0/n;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    if-ne p1, v1, :cond_3

    .line 78
    .line 79
    return-object v1

    .line 80
    :cond_3
    :goto_1
    const/4 p1, 0x0

    .line 81
    iput-boolean p1, p0, Lb0/d1;->d:Z

    .line 82
    .line 83
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 84
    .line 85
    return-object p0
.end method
