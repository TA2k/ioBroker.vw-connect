.class public final Landroidx/camera/core/internal/compat/quirk/ImageCaptureFailedForSpecificCombinationQuirk;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/p1;


# static fields
.field public static final a:Ljava/util/HashSet;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Ljava/util/HashSet;

    .line 2
    .line 3
    const-string v1, "pixel 5"

    .line 4
    .line 5
    const-string v2, "pixel 5a"

    .line 6
    .line 7
    const-string v3, "pixel 4a"

    .line 8
    .line 9
    const-string v4, "pixel 4a (5g)"

    .line 10
    .line 11
    filled-new-array {v3, v4, v1, v2}, [Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Landroidx/camera/core/internal/compat/quirk/ImageCaptureFailedForSpecificCombinationQuirk;->a:Ljava/util/HashSet;

    .line 23
    .line 24
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static b(Ljava/util/LinkedHashSet;)Z
    .locals 8

    .line 1
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x3

    .line 6
    const/4 v2, 0x0

    .line 7
    if-eq v0, v1, :cond_0

    .line 8
    .line 9
    goto :goto_1

    .line 10
    :cond_0
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    move v0, v2

    .line 15
    move v1, v0

    .line 16
    move v3, v1

    .line 17
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v4

    .line 21
    const/4 v5, 0x1

    .line 22
    if-eqz v4, :cond_5

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    check-cast v4, Lb0/z1;

    .line 29
    .line 30
    instance-of v6, v4, Lb0/k1;

    .line 31
    .line 32
    if-eqz v6, :cond_2

    .line 33
    .line 34
    move v0, v5

    .line 35
    goto :goto_0

    .line 36
    :cond_2
    instance-of v6, v4, Lb0/u0;

    .line 37
    .line 38
    if-eqz v6, :cond_3

    .line 39
    .line 40
    move v3, v5

    .line 41
    goto :goto_0

    .line 42
    :cond_3
    iget-object v6, v4, Lb0/z1;->g:Lh0/o2;

    .line 43
    .line 44
    sget-object v7, Lh0/o2;->Z0:Lh0/g;

    .line 45
    .line 46
    invoke-interface {v6, v7}, Lh0/t1;->j(Lh0/g;)Z

    .line 47
    .line 48
    .line 49
    move-result v6

    .line 50
    if-eqz v6, :cond_1

    .line 51
    .line 52
    iget-object v1, v4, Lb0/z1;->g:Lh0/o2;

    .line 53
    .line 54
    invoke-interface {v1}, Lh0/o2;->J()Lh0/q2;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    sget-object v4, Lh0/q2;->g:Lh0/q2;

    .line 59
    .line 60
    if-ne v1, v4, :cond_4

    .line 61
    .line 62
    move v1, v5

    .line 63
    goto :goto_0

    .line 64
    :cond_4
    move v1, v2

    .line 65
    goto :goto_0

    .line 66
    :cond_5
    if-eqz v0, :cond_6

    .line 67
    .line 68
    if-eqz v1, :cond_6

    .line 69
    .line 70
    if-eqz v3, :cond_6

    .line 71
    .line 72
    return v5

    .line 73
    :cond_6
    :goto_1
    return v2
.end method
