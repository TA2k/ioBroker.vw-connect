.class public Lcom/google/android/gms/internal/measurement/i4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/c1;
.implements Llo/n;


# static fields
.field public static h:Lcom/google/android/gms/internal/measurement/i4;


# instance fields
.field public final synthetic d:I

.field public e:Z

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 0

    iput p1, p0, Lcom/google/android/gms/internal/measurement/i4;->d:I

    packed-switch p1, :pswitch_data_0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p1, 0x0

    iput-boolean p1, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    const/4 p1, 0x0

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    return-void

    .line 2
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/lang/Object;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    return-void

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lcom/google/android/gms/internal/measurement/i4;->d:I

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean v0, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    new-instance p1, Lcom/google/android/gms/internal/measurement/h4;

    const/4 v0, 0x0

    .line 6
    invoke-direct {p1, v0}, Landroid/database/ContentObserver;-><init>(Landroid/os/Handler;)V

    .line 7
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/media/ImageReader;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lcom/google/android/gms/internal/measurement/i4;->d:I

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    const/4 v0, 0x1

    .line 13
    iput-boolean v0, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 14
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroidx/collection/u;Lc2/k;)V
    .locals 1

    const/16 v0, 0xa

    iput v0, p0, Lcom/google/android/gms/internal/measurement/i4;->d:I

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 10
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Le2/w0;)V
    .locals 1

    const/4 v0, 0x6

    iput v0, p0, Lcom/google/android/gms/internal/measurement/i4;->d:I

    .line 43
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 44
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    const/4 p1, 0x1

    .line 45
    iput-boolean p1, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    return-void
.end method

.method public constructor <init>(Lgp/a;Lis/b;)V
    .locals 1

    const/16 v0, 0x8

    iput v0, p0, Lcom/google/android/gms/internal/measurement/i4;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    const/4 p1, 0x1

    iput-boolean p1, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Z)V
    .locals 1

    const/16 v0, 0x9

    iput v0, p0, Lcom/google/android/gms/internal/measurement/i4;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    iput-boolean p3, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    return-void
.end method

.method public constructor <init>(Ljava/util/List;Ljava/util/Map;Z)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, Lcom/google/android/gms/internal/measurement/i4;->d:I

    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 17
    iput-boolean p3, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 18
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/util/concurrent/Executor;Landroid/hardware/camera2/CameraCharacteristics;)V
    .locals 2

    const/4 p2, 0x7

    iput p2, p0, Lcom/google/android/gms/internal/measurement/i4;->d:I

    .line 19
    sget-object p2, Lm0/a;->a:Ld01/x;

    .line 20
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 21
    const-class v0, Landroidx/camera/core/internal/compat/quirk/LowMemoryQuirk;

    .line 22
    sget-object v1, Lm0/a;->a:Ld01/x;

    invoke-virtual {v1, v0}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    move-result-object v0

    if-eqz v0, :cond_0

    .line 23
    new-instance v0, Lj0/h;

    invoke-direct {v0, p1}, Lj0/h;-><init>(Ljava/util/concurrent/Executor;)V

    .line 24
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    goto :goto_0

    .line 25
    :cond_0
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 26
    :goto_0
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 27
    const-class p1, Landroidx/camera/core/internal/compat/quirk/IncorrectJpegMetadataQuirk;

    invoke-virtual {p2, p1}, Ld01/x;->k(Ljava/lang/Class;)Z

    move-result p1

    iput-boolean p1, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    return-void
.end method

.method public constructor <init>(Lv/b;)V
    .locals 5

    const/16 v0, 0xb

    iput v0, p0, Lcom/google/android/gms/internal/measurement/i4;->d:I

    .line 28
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 29
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 30
    invoke-static {p1}, Lpv/g;->d(Lv/b;)Lpv/g;

    move-result-object v0

    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 31
    sget-object v0, Landroid/hardware/camera2/CameraCharacteristics;->REQUEST_AVAILABLE_CAPABILITIES:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 32
    invoke-virtual {p1, v0}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [I

    const/4 v0, 0x0

    if-eqz p1, :cond_1

    .line 33
    array-length v1, p1

    move v2, v0

    :goto_0
    if-ge v2, v1, :cond_1

    aget v3, p1, v2

    const/16 v4, 0x12

    if-ne v3, v4, :cond_0

    const/4 v0, 0x1

    goto :goto_1

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 34
    :cond_1
    :goto_1
    iput-boolean v0, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    return-void
.end method

.method public constructor <init>(Lvy0/b0;ZLay0/n;Lc/l;)V
    .locals 6

    const/4 v0, 0x3

    iput v0, p0, Lcom/google/android/gms/internal/measurement/i4;->d:I

    .line 35
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 36
    iput-boolean p2, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 37
    sget-object p2, Lxy0/a;->d:Lxy0/a;

    const/4 v0, 0x4

    const/4 v1, -0x2

    invoke-static {v1, v0, p2}, Llp/jf;->a(IILxy0/a;)Lxy0/j;

    move-result-object p2

    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 38
    new-instance v0, La7/k;

    const/16 v1, 0xa

    const/4 v5, 0x0

    move-object v4, p0

    move-object v3, p3

    move-object v2, p4

    invoke-direct/range {v0 .. v5}, La7/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    const/4 p0, 0x3

    invoke-static {p1, v5, v5, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    move-result-object p0

    iput-object p0, v4, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lxw/h;Z)V
    .locals 1

    const/16 v0, 0xc

    iput v0, p0, Lcom/google/android/gms/internal/measurement/i4;->d:I

    .line 46
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 47
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 48
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 49
    iput-boolean p2, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    return-void
.end method

.method public constructor <init>(ZLe2/s;Landroidx/collection/h;)V
    .locals 1

    const/4 v0, 0x5

    iput v0, p0, Lcom/google/android/gms/internal/measurement/i4;->d:I

    .line 39
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 40
    iput-boolean p1, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 41
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 42
    iput-object p3, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    return-void
.end method

.method public static j(Lb0/y;Lb0/y;)Z
    .locals 4

    .line 1
    invoke-virtual {p1}, Lb0/y;->b()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget v1, p1, Lb0/y;->a:I

    .line 6
    .line 7
    const-string v2, "Fully specified range is not actually fully specified."

    .line 8
    .line 9
    invoke-static {v2, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 10
    .line 11
    .line 12
    iget v0, p0, Lb0/y;->a:I

    .line 13
    .line 14
    const/4 v2, 0x1

    .line 15
    const/4 v3, 0x2

    .line 16
    if-ne v0, v3, :cond_0

    .line 17
    .line 18
    if-ne v1, v2, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    if-eq v0, v3, :cond_1

    .line 22
    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    if-eq v0, v1, :cond_1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    iget p0, p0, Lb0/y;->b:I

    .line 29
    .line 30
    if-eqz p0, :cond_3

    .line 31
    .line 32
    iget p1, p1, Lb0/y;->b:I

    .line 33
    .line 34
    if-ne p0, p1, :cond_2

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 38
    return p0

    .line 39
    :cond_3
    :goto_1
    return v2
.end method

.method public static k(Lb0/y;Lb0/y;Ljava/util/HashSet;)Z
    .locals 1

    .line 1
    invoke-virtual {p2, p1}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    if-nez p2, :cond_0

    .line 6
    .line 7
    new-instance p2, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v0, "Candidate Dynamic range is not within constraints.\nDynamic range to resolve:\n  "

    .line 10
    .line 11
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p0, "\nCandidate dynamic range:\n  "

    .line 18
    .line 19
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    const-string p1, "DynamicRangeResolver"

    .line 30
    .line 31
    invoke-static {p1, p0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const/4 p0, 0x0

    .line 35
    return p0

    .line 36
    :cond_0
    invoke-static {p0, p1}, Lcom/google/android/gms/internal/measurement/i4;->j(Lb0/y;Lb0/y;)Z

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    return p0
.end method

.method public static n(Ljava/lang/Class;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Class;->getModifiers()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {v0}, Ljava/lang/reflect/Modifier;->isInterface(I)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    const-string v0, "Interfaces can\'t be instantiated! Register an InstanceCreator or a TypeAdapter for this type. Interface name: "

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :cond_0
    invoke-static {v0}, Ljava/lang/reflect/Modifier;->isAbstract(I)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    new-instance v0, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    const-string v1, "Abstract classes can\'t be instantiated! Adjust the R8 configuration or register an InstanceCreator or a TypeAdapter for this type. Class name: "

    .line 31
    .line 32
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string p0, "\nSee "

    .line 43
    .line 44
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string p0, "r8-abstract-class"

    .line 48
    .line 49
    const-string v1, "https://github.com/google/gson/blob/main/Troubleshooting.md#"

    .line 50
    .line 51
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0

    .line 63
    :cond_1
    const/4 p0, 0x0

    .line 64
    return-object p0
.end method

.method public static p(Lb0/y;Ljava/util/LinkedHashSet;Ljava/util/HashSet;)Lb0/y;
    .locals 5

    .line 1
    iget v0, p0, Lb0/y;->a:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-ne v0, v1, :cond_0

    .line 5
    .line 6
    goto :goto_1

    .line 7
    :cond_0
    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    :cond_1
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_3

    .line 16
    .line 17
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lb0/y;

    .line 22
    .line 23
    const-string v2, "Fully specified DynamicRange cannot be null."

    .line 24
    .line 25
    invoke-static {v0, v2}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iget v2, v0, Lb0/y;->a:I

    .line 29
    .line 30
    invoke-virtual {v0}, Lb0/y;->b()Z

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    const-string v4, "Fully specified DynamicRange must have fully defined encoding."

    .line 35
    .line 36
    invoke-static {v4, v3}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 37
    .line 38
    .line 39
    if-ne v2, v1, :cond_2

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_2
    invoke-static {p0, v0, p2}, Lcom/google/android/gms/internal/measurement/i4;->k(Lb0/y;Lb0/y;Ljava/util/HashSet;)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-eqz v2, :cond_1

    .line 47
    .line 48
    return-object v0

    .line 49
    :cond_3
    :goto_1
    const/4 p0, 0x0

    .line 50
    return-object p0
.end method

.method public static u(ILjava/lang/String;)V
    .locals 3

    .line 1
    const/16 v0, 0xa

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Ljava/lang/String;->indexOf(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, -0x1

    .line 8
    if-ne v0, v1, :cond_0

    .line 9
    .line 10
    const/16 v0, 0xd

    .line 11
    .line 12
    invoke-virtual {p1, v0}, Ljava/lang/String;->indexOf(I)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-ne v0, v1, :cond_0

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    new-instance v0, Lxw/r;

    .line 20
    .line 21
    const-string v1, "Invalid tag name: contains newline \'"

    .line 22
    .line 23
    const-string v2, "\'"

    .line 24
    .line 25
    invoke-static {v1, p1, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-direct {v0, p1, p0}, Lxw/r;-><init>(Ljava/lang/String;I)V

    .line 30
    .line 31
    .line 32
    throw v0
.end method

.method public static v(Ljava/lang/String;ILjava/lang/String;)V
    .locals 4

    .line 1
    invoke-virtual {p0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    new-instance v0, Lxw/r;

    .line 9
    .line 10
    const-string v1, "\' != \'"

    .line 11
    .line 12
    const-string v2, "\'"

    .line 13
    .line 14
    const-string v3, "Section close tag with mismatched open tag \'"

    .line 15
    .line 16
    invoke-static {v3, p2, v1, p0, v2}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-direct {v0, p0, p1}, Lxw/r;-><init>(Ljava/lang/String;I)V

    .line 21
    .line 22
    .line 23
    throw v0
.end method

.method public static w(Ljava/util/HashSet;Lb0/y;Lpv/g;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/util/HashSet;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    xor-int/lit8 v0, v0, 0x1

    .line 6
    .line 7
    const-string v1, "Cannot update already-empty constraints."

    .line 8
    .line 9
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 10
    .line 11
    .line 12
    iget-object p2, p2, Lpv/g;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p2, Lw/b;

    .line 15
    .line 16
    invoke-interface {p2, p1}, Lw/b;->b(Lb0/y;)Ljava/util/Set;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    invoke-interface {p2}, Ljava/util/Set;->isEmpty()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    new-instance v0, Ljava/util/HashSet;

    .line 27
    .line 28
    invoke-direct {v0, p0}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 29
    .line 30
    .line 31
    invoke-interface {p0, p2}, Ljava/util/Set;->retainAll(Ljava/util/Collection;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Ljava/util/HashSet;->isEmpty()Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-nez p0, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 42
    .line 43
    const-string v1, "\n  "

    .line 44
    .line 45
    invoke-static {v1, p2}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p2

    .line 49
    invoke-static {v1, v0}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    new-instance v1, Ljava/lang/StringBuilder;

    .line 54
    .line 55
    const-string v2, "Constraints of dynamic range cannot be combined with existing constraints.\nDynamic range:\n  "

    .line 56
    .line 57
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string p1, "\nConstraints:\n  "

    .line 64
    .line 65
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    const-string p1, "\nExisting constraints:\n  "

    .line 72
    .line 73
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw p0

    .line 87
    :cond_1
    :goto_0
    return-void
.end method

.method public static y(Landroid/content/Context;)Lcom/google/android/gms/internal/measurement/i4;
    .locals 4

    .line 1
    const-class v0, Lcom/google/android/gms/internal/measurement/i4;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lcom/google/android/gms/internal/measurement/i4;->h:Lcom/google/android/gms/internal/measurement/i4;

    .line 5
    .line 6
    if-nez v1, :cond_1

    .line 7
    .line 8
    const-string v1, "com.google.android.providers.gsf.permission.READ_GSERVICES"

    .line 9
    .line 10
    invoke-static {p0, v1}, Ln5/a;->b(Landroid/content/Context;Ljava/lang/String;)I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    new-instance v1, Lcom/google/android/gms/internal/measurement/i4;

    .line 17
    .line 18
    invoke-direct {v1, p0}, Lcom/google/android/gms/internal/measurement/i4;-><init>(Landroid/content/Context;)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catchall_0
    move-exception p0

    .line 23
    goto :goto_2

    .line 24
    :cond_0
    new-instance v1, Lcom/google/android/gms/internal/measurement/i4;

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    invoke-direct {v1, v2}, Lcom/google/android/gms/internal/measurement/i4;-><init>(I)V

    .line 28
    .line 29
    .line 30
    :goto_0
    sput-object v1, Lcom/google/android/gms/internal/measurement/i4;->h:Lcom/google/android/gms/internal/measurement/i4;

    .line 31
    .line 32
    :cond_1
    sget-object v1, Lcom/google/android/gms/internal/measurement/i4;->h:Lcom/google/android/gms/internal/measurement/i4;

    .line 33
    .line 34
    if-eqz v1, :cond_2

    .line 35
    .line 36
    iget-object v2, v1, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v2, Lcom/google/android/gms/internal/measurement/h4;

    .line 39
    .line 40
    if-eqz v2, :cond_2

    .line 41
    .line 42
    iget-boolean v1, v1, Lcom/google/android/gms/internal/measurement/i4;->e:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    .line 44
    if-nez v1, :cond_2

    .line 45
    .line 46
    :try_start_1
    invoke-virtual {p0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    sget-object v1, Lcom/google/android/gms/internal/measurement/y3;->a:Landroid/net/Uri;

    .line 51
    .line 52
    sget-object v2, Lcom/google/android/gms/internal/measurement/i4;->h:Lcom/google/android/gms/internal/measurement/i4;

    .line 53
    .line 54
    iget-object v2, v2, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v2, Lcom/google/android/gms/internal/measurement/h4;

    .line 57
    .line 58
    const/4 v3, 0x1

    .line 59
    invoke-virtual {p0, v1, v3, v2}, Landroid/content/ContentResolver;->registerContentObserver(Landroid/net/Uri;ZLandroid/database/ContentObserver;)V

    .line 60
    .line 61
    .line 62
    sget-object p0, Lcom/google/android/gms/internal/measurement/i4;->h:Lcom/google/android/gms/internal/measurement/i4;

    .line 63
    .line 64
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    iput-boolean v3, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z
    :try_end_1
    .catch Ljava/lang/SecurityException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :catch_0
    move-exception p0

    .line 71
    :try_start_2
    const-string v1, "GservicesLoader"

    .line 72
    .line 73
    const-string v2, "Unable to register Gservices content observer"

    .line 74
    .line 75
    invoke-static {v1, v2, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 76
    .line 77
    .line 78
    :cond_2
    :goto_1
    sget-object p0, Lcom/google/android/gms/internal/measurement/i4;->h:Lcom/google/android/gms/internal/measurement/i4;

    .line 79
    .line 80
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 81
    .line 82
    .line 83
    monitor-exit v0

    .line 84
    return-object p0

    .line 85
    :goto_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 86
    throw p0
.end method


# virtual methods
.method public A(Laq/r;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v1, Ljava/util/ArrayDeque;

    .line 7
    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    new-instance v1, Ljava/util/ArrayDeque;

    .line 11
    .line 12
    invoke-direct {v1}, Ljava/util/ArrayDeque;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object v1, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :catchall_0
    move-exception p0

    .line 19
    goto :goto_1

    .line 20
    :cond_0
    :goto_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Ljava/util/ArrayDeque;

    .line 23
    .line 24
    invoke-virtual {p0, p1}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    monitor-exit v0

    .line 28
    return-void

    .line 29
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    throw p0
.end method

.method public B(Ljava/lang/String;)Ljava/lang/String;
    .locals 8

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/content/Context;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_9

    .line 7
    .line 8
    sget-boolean v2, Lcom/google/android/gms/internal/measurement/c4;->b:Z

    .line 9
    .line 10
    const/4 v3, 0x1

    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    goto :goto_3

    .line 14
    :cond_0
    const-class v2, Lcom/google/android/gms/internal/measurement/c4;

    .line 15
    .line 16
    monitor-enter v2

    .line 17
    :try_start_0
    sget-boolean v4, Lcom/google/android/gms/internal/measurement/c4;->b:Z

    .line 18
    .line 19
    if-eqz v4, :cond_1

    .line 20
    .line 21
    monitor-exit v2

    .line 22
    goto :goto_3

    .line 23
    :catchall_0
    move-exception p0

    .line 24
    goto/16 :goto_6

    .line 25
    .line 26
    :cond_1
    move v4, v3

    .line 27
    :goto_0
    const/4 v5, 0x2

    .line 28
    const/4 v6, 0x0

    .line 29
    if-gt v4, v5, :cond_5

    .line 30
    .line 31
    sget-object v5, Lcom/google/android/gms/internal/measurement/c4;->a:Landroid/os/UserManager;

    .line 32
    .line 33
    if-nez v5, :cond_2

    .line 34
    .line 35
    const-class v5, Landroid/os/UserManager;

    .line 36
    .line 37
    invoke-virtual {v0, v5}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v5

    .line 41
    check-cast v5, Landroid/os/UserManager;

    .line 42
    .line 43
    sput-object v5, Lcom/google/android/gms/internal/measurement/c4;->a:Landroid/os/UserManager;

    .line 44
    .line 45
    :cond_2
    sget-object v5, Lcom/google/android/gms/internal/measurement/c4;->a:Landroid/os/UserManager;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 46
    .line 47
    if-nez v5, :cond_3

    .line 48
    .line 49
    move v6, v3

    .line 50
    goto :goto_2

    .line 51
    :cond_3
    :try_start_1
    invoke-virtual {v5}, Landroid/os/UserManager;->isUserUnlocked()Z

    .line 52
    .line 53
    .line 54
    move-result v7

    .line 55
    if-nez v7, :cond_4

    .line 56
    .line 57
    invoke-static {}, Landroid/os/Process;->myUserHandle()Landroid/os/UserHandle;

    .line 58
    .line 59
    .line 60
    move-result-object v7

    .line 61
    invoke-virtual {v5, v7}, Landroid/os/UserManager;->isUserRunning(Landroid/os/UserHandle;)Z

    .line 62
    .line 63
    .line 64
    move-result v0
    :try_end_1
    .catch Ljava/lang/NullPointerException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 65
    if-nez v0, :cond_5

    .line 66
    .line 67
    :cond_4
    move v6, v3

    .line 68
    goto :goto_1

    .line 69
    :catch_0
    move-exception v5

    .line 70
    :try_start_2
    const-string v6, "DirectBootUtils"

    .line 71
    .line 72
    const-string v7, "Failed to check if user is unlocked."

    .line 73
    .line 74
    invoke-static {v6, v7, v5}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 75
    .line 76
    .line 77
    sput-object v1, Lcom/google/android/gms/internal/measurement/c4;->a:Landroid/os/UserManager;

    .line 78
    .line 79
    add-int/lit8 v4, v4, 0x1

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_5
    :goto_1
    if-eqz v6, :cond_6

    .line 83
    .line 84
    sput-object v1, Lcom/google/android/gms/internal/measurement/c4;->a:Landroid/os/UserManager;

    .line 85
    .line 86
    :cond_6
    :goto_2
    if-eqz v6, :cond_7

    .line 87
    .line 88
    sput-boolean v3, Lcom/google/android/gms/internal/measurement/c4;->b:Z

    .line 89
    .line 90
    :cond_7
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 91
    move v3, v6

    .line 92
    :goto_3
    if-nez v3, :cond_8

    .line 93
    .line 94
    goto :goto_7

    .line 95
    :cond_8
    :try_start_3
    new-instance v0, Lcom/google/android/gms/internal/measurement/u;

    .line 96
    .line 97
    invoke-direct {v0, p0, p1}, Lcom/google/android/gms/internal/measurement/u;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_3
    .catch Ljava/lang/IllegalStateException; {:try_start_3 .. :try_end_3} :catch_2
    .catch Ljava/lang/SecurityException; {:try_start_3 .. :try_end_3} :catch_2
    .catch Ljava/lang/NullPointerException; {:try_start_3 .. :try_end_3} :catch_2

    .line 98
    .line 99
    .line 100
    :try_start_4
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/u;->a()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0
    :try_end_4
    .catch Ljava/lang/SecurityException; {:try_start_4 .. :try_end_4} :catch_1
    .catch Ljava/lang/IllegalStateException; {:try_start_4 .. :try_end_4} :catch_2
    .catch Ljava/lang/NullPointerException; {:try_start_4 .. :try_end_4} :catch_2

    .line 104
    goto :goto_4

    .line 105
    :catch_1
    :try_start_5
    invoke-static {}, Landroid/os/Binder;->clearCallingIdentity()J

    .line 106
    .line 107
    .line 108
    move-result-wide v2
    :try_end_5
    .catch Ljava/lang/IllegalStateException; {:try_start_5 .. :try_end_5} :catch_2
    .catch Ljava/lang/SecurityException; {:try_start_5 .. :try_end_5} :catch_2
    .catch Ljava/lang/NullPointerException; {:try_start_5 .. :try_end_5} :catch_2

    .line 109
    :try_start_6
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/u;->a()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 113
    :try_start_7
    invoke-static {v2, v3}, Landroid/os/Binder;->restoreCallingIdentity(J)V

    .line 114
    .line 115
    .line 116
    :goto_4
    check-cast p0, Ljava/lang/String;

    .line 117
    .line 118
    return-object p0

    .line 119
    :catch_2
    move-exception p0

    .line 120
    goto :goto_5

    .line 121
    :catchall_1
    move-exception p0

    .line 122
    invoke-static {v2, v3}, Landroid/os/Binder;->restoreCallingIdentity(J)V

    .line 123
    .line 124
    .line 125
    throw p0
    :try_end_7
    .catch Ljava/lang/IllegalStateException; {:try_start_7 .. :try_end_7} :catch_2
    .catch Ljava/lang/SecurityException; {:try_start_7 .. :try_end_7} :catch_2
    .catch Ljava/lang/NullPointerException; {:try_start_7 .. :try_end_7} :catch_2

    .line 126
    :goto_5
    const-string v0, "Unable to read GServices for: "

    .line 127
    .line 128
    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    const-string v0, "GservicesLoader"

    .line 133
    .line 134
    invoke-static {v0, p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 135
    .line 136
    .line 137
    return-object v1

    .line 138
    :goto_6
    :try_start_8
    monitor-exit v2
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 139
    throw p0

    .line 140
    :cond_9
    :goto_7
    return-object v1
.end method

.method public C(Laq/j;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v1, Ljava/util/ArrayDeque;

    .line 7
    .line 8
    if-eqz v1, :cond_2

    .line 9
    .line 10
    iget-boolean v1, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 11
    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    goto :goto_2

    .line 15
    :cond_0
    const/4 v1, 0x1

    .line 16
    iput-boolean v1, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 17
    .line 18
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 19
    :goto_0
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 20
    .line 21
    monitor-enter v1

    .line 22
    :try_start_1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v0, Ljava/util/ArrayDeque;

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->poll()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    check-cast v0, Laq/r;

    .line 31
    .line 32
    if-nez v0, :cond_1

    .line 33
    .line 34
    const/4 p1, 0x0

    .line 35
    iput-boolean p1, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 36
    .line 37
    monitor-exit v1

    .line 38
    return-void

    .line 39
    :catchall_0
    move-exception p0

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 42
    invoke-interface {v0, p1}, Laq/r;->a(Laq/j;)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :goto_1
    :try_start_2
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 47
    throw p0

    .line 48
    :catchall_1
    move-exception p0

    .line 49
    goto :goto_3

    .line 50
    :cond_2
    :goto_2
    :try_start_3
    monitor-exit v0

    .line 51
    return-void

    .line 52
    :goto_3
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 53
    throw p0
.end method

.method public a(J)Z
    .locals 6

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lc2/k;

    .line 4
    .line 5
    iget-object p0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ljava/util/List;

    .line 8
    .line 9
    move-object v0, p0

    .line 10
    check-cast v0, Ljava/util/Collection;

    .line 11
    .line 12
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/4 v1, 0x0

    .line 17
    move v2, v1

    .line 18
    :goto_0
    if-ge v2, v0, :cond_1

    .line 19
    .line 20
    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    move-object v4, v3

    .line 25
    check-cast v4, Lp3/v;

    .line 26
    .line 27
    iget-wide v4, v4, Lp3/v;->a:J

    .line 28
    .line 29
    invoke-static {v4, v5, p1, p2}, Lp3/s;->e(JJ)Z

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    if-eqz v4, :cond_0

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    const/4 v3, 0x0

    .line 40
    :goto_1
    check-cast v3, Lp3/v;

    .line 41
    .line 42
    if-eqz v3, :cond_2

    .line 43
    .line 44
    iget-boolean p0, v3, Lp3/v;->h:Z

    .line 45
    .line 46
    return p0

    .line 47
    :cond_2
    return v1
.end method

.method public accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 12

    .line 1
    check-cast p1, Lgp/f;

    .line 2
    .line 3
    check-cast p2, Laq/k;

    .line 4
    .line 5
    monitor-enter p0

    .line 6
    :try_start_0
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lis/b;

    .line 9
    .line 10
    iget-object v0, v0, Lis/b;->c:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Llo/k;

    .line 13
    .line 14
    iget-boolean v1, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 15
    .line 16
    iget-object v2, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v2, Lis/b;

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    iput-object v3, v2, Lis/b;->b:Ljava/lang/Object;

    .line 22
    .line 23
    iput-object v3, v2, Lis/b;->c:Ljava/lang/Object;

    .line 24
    .line 25
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 26
    if-nez v0, :cond_0

    .line 27
    .line 28
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 29
    .line 30
    invoke-virtual {p2, p0}, Laq/k;->b(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_0
    iget-object v2, p1, Lgp/f;->A:Landroidx/collection/a1;

    .line 35
    .line 36
    monitor-enter v2

    .line 37
    :try_start_1
    iget-object p0, p1, Lgp/f;->A:Landroidx/collection/a1;

    .line 38
    .line 39
    invoke-virtual {p0, v0}, Landroidx/collection/a1;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    move-object v7, p0

    .line 44
    check-cast v7, Lgp/e;

    .line 45
    .line 46
    if-nez v7, :cond_1

    .line 47
    .line 48
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 49
    .line 50
    invoke-virtual {p2, p0}, Laq/k;->b(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    monitor-exit v2

    .line 54
    return-void

    .line 55
    :catchall_0
    move-exception v0

    .line 56
    move-object p0, v0

    .line 57
    goto/16 :goto_4

    .line 58
    .line 59
    :cond_1
    iget-object p0, v7, Lgp/e;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 60
    .line 61
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/i4;->z()Lis/b;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    iput-object v3, p0, Lis/b;->b:Ljava/lang/Object;

    .line 66
    .line 67
    iput-object v3, p0, Lis/b;->c:Ljava/lang/Object;

    .line 68
    .line 69
    if-eqz v1, :cond_6

    .line 70
    .line 71
    invoke-virtual {p1}, Lno/e;->k()[Ljo/d;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    if-eqz p0, :cond_5

    .line 76
    .line 77
    const/4 v0, 0x0

    .line 78
    :goto_0
    array-length v1, p0

    .line 79
    if-ge v0, v1, :cond_3

    .line 80
    .line 81
    aget-object v1, p0, v0

    .line 82
    .line 83
    const-string v4, "location_updates_with_callback"

    .line 84
    .line 85
    iget-object v5, v1, Ljo/d;->d:Ljava/lang/String;

    .line 86
    .line 87
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v4

    .line 91
    if-eqz v4, :cond_2

    .line 92
    .line 93
    move-object v3, v1

    .line 94
    goto :goto_1

    .line 95
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_3
    :goto_1
    if-nez v3, :cond_4

    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_4
    invoke-virtual {v3}, Ljo/d;->x0()J

    .line 102
    .line 103
    .line 104
    move-result-wide v0

    .line 105
    const-wide/16 v3, 0x1

    .line 106
    .line 107
    cmp-long p0, v0, v3

    .line 108
    .line 109
    if-ltz p0, :cond_5

    .line 110
    .line 111
    invoke-virtual {p1}, Lno/e;->r()Landroid/os/IInterface;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    check-cast p0, Lgp/v;

    .line 116
    .line 117
    const-string p1, "ILocationCallback@"

    .line 118
    .line 119
    invoke-static {v7}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 120
    .line 121
    .line 122
    move-result v0

    .line 123
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 128
    .line 129
    .line 130
    move-result v1

    .line 131
    add-int/lit8 v1, v1, 0x12

    .line 132
    .line 133
    new-instance v3, Ljava/lang/StringBuilder;

    .line 134
    .line 135
    invoke-direct {v3, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v9

    .line 148
    new-instance v4, Lgp/h;

    .line 149
    .line 150
    const/4 v5, 0x2

    .line 151
    const/4 v8, 0x0

    .line 152
    const/4 v6, 0x0

    .line 153
    invoke-direct/range {v4 .. v9}, Lgp/h;-><init>(ILandroid/os/IBinder;Landroid/os/IBinder;Landroid/app/PendingIntent;Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 157
    .line 158
    new-instance v0, Lbp/r;

    .line 159
    .line 160
    const/4 v1, 0x1

    .line 161
    invoke-direct {v0, p1, p2, v1}, Lbp/r;-><init>(Ljava/lang/Object;Laq/k;I)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 165
    .line 166
    .line 167
    move-result-object p1

    .line 168
    invoke-static {p1, v4}, Lgp/b;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 172
    .line 173
    .line 174
    const/16 p2, 0x59

    .line 175
    .line 176
    invoke-virtual {p0, p1, p2}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 177
    .line 178
    .line 179
    goto :goto_3

    .line 180
    :cond_5
    :goto_2
    invoke-virtual {p1}, Lno/e;->r()Landroid/os/IInterface;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    check-cast p0, Lgp/v;

    .line 185
    .line 186
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 187
    .line 188
    new-instance v10, Lgp/c;

    .line 189
    .line 190
    invoke-direct {v10, p1, p2}, Lgp/c;-><init>(Ljava/lang/Boolean;Laq/k;)V

    .line 191
    .line 192
    .line 193
    new-instance v4, Lgp/j;

    .line 194
    .line 195
    const/4 v9, 0x0

    .line 196
    const/4 v11, 0x0

    .line 197
    const/4 v5, 0x2

    .line 198
    const/4 v6, 0x0

    .line 199
    move-object v8, v7

    .line 200
    const/4 v7, 0x0

    .line 201
    invoke-direct/range {v4 .. v11}, Lgp/j;-><init>(ILgp/i;Landroid/os/IBinder;Landroid/os/IBinder;Landroid/app/PendingIntent;Landroid/os/IBinder;Ljava/lang/String;)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 205
    .line 206
    .line 207
    move-result-object p1

    .line 208
    invoke-static {p1, v4}, Lgp/b;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 209
    .line 210
    .line 211
    const/16 p2, 0x3b

    .line 212
    .line 213
    invoke-virtual {p0, p1, p2}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 214
    .line 215
    .line 216
    goto :goto_3

    .line 217
    :cond_6
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 218
    .line 219
    invoke-virtual {p2, p0}, Laq/k;->b(Ljava/lang/Object;)V

    .line 220
    .line 221
    .line 222
    :goto_3
    monitor-exit v2

    .line 223
    return-void

    .line 224
    :goto_4
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 225
    throw p0

    .line 226
    :catchall_1
    move-exception v0

    .line 227
    move-object p1, v0

    .line 228
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 229
    throw p1
.end method

.method public b()Lb0/a1;
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    const/4 v1, 0x0

    .line 5
    :try_start_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Landroid/media/ImageReader;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/media/ImageReader;->acquireLatestImage()Landroid/media/Image;

    .line 10
    .line 11
    .line 12
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    goto :goto_0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    goto :goto_1

    .line 16
    :catch_0
    move-exception p0

    .line 17
    :try_start_1
    const-string v2, "ImageReaderContext is not initialized"

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_1

    .line 28
    .line 29
    move-object p0, v1

    .line 30
    :goto_0
    if-nez p0, :cond_0

    .line 31
    .line 32
    monitor-exit v0

    .line 33
    return-object v1

    .line 34
    :cond_0
    new-instance v1, Lb0/a;

    .line 35
    .line 36
    invoke-direct {v1, p0}, Lb0/a;-><init>(Landroid/media/Image;)V

    .line 37
    .line 38
    .line 39
    monitor-exit v0

    .line 40
    return-object v1

    .line 41
    :cond_1
    throw p0

    .line 42
    :goto_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 43
    throw p0
.end method

.method public c(ILjava/lang/String;)Lcom/google/android/gms/internal/measurement/i4;
    .locals 2

    .line 1
    new-instance p0, Lxw/r;

    .line 2
    .line 3
    const-string v0, "Section close tag with no open tag \'"

    .line 4
    .line 5
    const-string v1, "\'"

    .line 6
    .line 7
    invoke-static {v0, p2, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p2

    .line 11
    invoke-direct {p0, p2, p1}, Lxw/r;-><init>(Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    throw p0
.end method

.method public close()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Landroid/media/ImageReader;

    .line 7
    .line 8
    invoke-virtual {p0}, Landroid/media/ImageReader;->close()V

    .line 9
    .line 10
    .line 11
    monitor-exit v0

    .line 12
    return-void

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    throw p0
.end method

.method public d()I
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Landroid/media/ImageReader;

    .line 7
    .line 8
    invoke-virtual {p0}, Landroid/media/ImageReader;->getImageFormat()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    monitor-exit v0

    .line 13
    return p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public e()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    const/4 v1, 0x1

    .line 5
    :try_start_0
    iput-boolean v1, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 6
    .line 7
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Landroid/media/ImageReader;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-virtual {p0, v1, v1}, Landroid/media/ImageReader;->setOnImageAvailableListener(Landroid/media/ImageReader$OnImageAvailableListener;Landroid/os/Handler;)V

    .line 13
    .line 14
    .line 15
    monitor-exit v0

    .line 16
    return-void

    .line 17
    :catchall_0
    move-exception p0

    .line 18
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    throw p0
.end method

.method public f()I
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Landroid/media/ImageReader;

    .line 7
    .line 8
    invoke-virtual {p0}, Landroid/media/ImageReader;->getMaxImages()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    monitor-exit v0

    .line 13
    return p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public g(Lh0/b1;Ljava/util/concurrent/Executor;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    const/4 v1, 0x0

    .line 5
    :try_start_0
    iput-boolean v1, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 6
    .line 7
    new-instance v1, Lb0/b;

    .line 8
    .line 9
    invoke-direct {v1, p0, p2, p1}, Lb0/b;-><init>(Lcom/google/android/gms/internal/measurement/i4;Ljava/util/concurrent/Executor;Lh0/b1;)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Landroid/media/ImageReader;

    .line 15
    .line 16
    invoke-static {}, Li0/d;->c()Landroid/os/Handler;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-virtual {p0, v1, p1}, Landroid/media/ImageReader;->setOnImageAvailableListener(Landroid/media/ImageReader$OnImageAvailableListener;Landroid/os/Handler;)V

    .line 21
    .line 22
    .line 23
    monitor-exit v0

    .line 24
    return-void

    .line 25
    :catchall_0
    move-exception p0

    .line 26
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    throw p0
.end method

.method public getSurface()Landroid/view/Surface;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Landroid/media/ImageReader;

    .line 7
    .line 8
    invoke-virtual {p0}, Landroid/media/ImageReader;->getSurface()Landroid/view/Surface;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    monitor-exit v0

    .line 13
    return-object p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public h()Lb0/a1;
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    const/4 v1, 0x0

    .line 5
    :try_start_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Landroid/media/ImageReader;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/media/ImageReader;->acquireNextImage()Landroid/media/Image;

    .line 10
    .line 11
    .line 12
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    goto :goto_0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    goto :goto_1

    .line 16
    :catch_0
    move-exception p0

    .line 17
    :try_start_1
    const-string v2, "ImageReaderContext is not initialized"

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_1

    .line 28
    .line 29
    move-object p0, v1

    .line 30
    :goto_0
    if-nez p0, :cond_0

    .line 31
    .line 32
    monitor-exit v0

    .line 33
    return-object v1

    .line 34
    :cond_0
    new-instance v1, Lb0/a;

    .line 35
    .line 36
    invoke-direct {v1, p0}, Lb0/a;-><init>(Landroid/media/Image;)V

    .line 37
    .line 38
    .line 39
    monitor-exit v0

    .line 40
    return-object v1

    .line 41
    :cond_1
    throw p0

    .line 42
    :goto_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 43
    throw p0
.end method

.method public i(Ljava/lang/StringBuilder;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->length()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-lez v1, :cond_1

    .line 10
    .line 11
    new-instance v1, Lxw/o;

    .line 12
    .line 13
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    const/4 v4, 0x1

    .line 22
    const/4 v5, 0x0

    .line 23
    if-eqz v3, :cond_0

    .line 24
    .line 25
    iget-boolean p0, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 26
    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    move p0, v4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move p0, v5

    .line 32
    :goto_0
    invoke-static {v2, v4, p0}, Lxw/o;->b(Ljava/lang/String;ZZ)I

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    invoke-static {v2, v5, p0}, Lxw/o;->b(Ljava/lang/String;ZZ)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    invoke-direct {v1, v2, v3, p0}, Lxw/o;-><init>(Ljava/lang/String;II)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    invoke-virtual {p1, v5}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 47
    .line 48
    .line 49
    :cond_1
    return-void
.end method

.method public l()V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lxy0/j;

    .line 4
    .line 5
    new-instance v1, Ljava/util/concurrent/CancellationException;

    .line 6
    .line 7
    const-string v2, "onBack cancelled"

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-virtual {v0, v1, v2}, Lxy0/j;->j(Ljava/lang/Throwable;Z)Z

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lvy0/x1;

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    invoke-virtual {p0, v0}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public m()I
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Landroid/media/ImageReader;

    .line 7
    .line 8
    invoke-virtual {p0}, Landroid/media/ImageReader;->getHeight()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    monitor-exit v0

    .line 13
    return p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public o()I
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Landroid/media/ImageReader;

    .line 7
    .line 8
    invoke-virtual {p0}, Landroid/media/ImageReader;->getWidth()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    monitor-exit v0

    .line 13
    return p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public q()[Lxw/u;
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    new-array v0, v0, [Lxw/u;

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, [Lxw/u;

    .line 16
    .line 17
    return-object p0
.end method

.method public r(Lcom/google/gson/reflect/TypeToken;Z)Lcom/google/gson/internal/m;
    .locals 8

    .line 1
    invoke-virtual {p1}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p1}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Ljava/util/Map;

    .line 12
    .line 13
    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    if-nez v2, :cond_17

    .line 18
    .line 19
    invoke-interface {v1, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    if-nez v1, :cond_16

    .line 24
    .line 25
    const-class v1, Ljava/util/EnumSet;

    .line 26
    .line 27
    invoke-virtual {v1, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    const/4 v2, 0x1

    .line 32
    const/4 v3, 0x0

    .line 33
    const/4 v4, 0x0

    .line 34
    if-eqz v1, :cond_0

    .line 35
    .line 36
    new-instance v1, Lcom/google/gson/internal/b;

    .line 37
    .line 38
    invoke-direct {v1, v3, v0}, Lcom/google/gson/internal/b;-><init>(ILjava/lang/reflect/Type;)V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const-class v1, Ljava/util/EnumMap;

    .line 43
    .line 44
    if-ne p1, v1, :cond_1

    .line 45
    .line 46
    new-instance v1, Lcom/google/gson/internal/b;

    .line 47
    .line 48
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/b;-><init>(ILjava/lang/reflect/Type;)V

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    move-object v1, v4

    .line 53
    :goto_0
    if-eqz v1, :cond_2

    .line 54
    .line 55
    return-object v1

    .line 56
    :cond_2
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v1, Ljava/util/List;

    .line 59
    .line 60
    invoke-static {v1}, Lcom/google/gson/internal/f;->f(Ljava/util/List;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {p1}, Ljava/lang/Class;->getModifiers()I

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    invoke-static {v1}, Ljava/lang/reflect/Modifier;->isAbstract(I)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-eqz v1, :cond_3

    .line 72
    .line 73
    :catch_0
    move-object v1, v4

    .line 74
    goto :goto_2

    .line 75
    :cond_3
    :try_start_0
    invoke-virtual {p1, v4}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 76
    .line 77
    .line 78
    move-result-object v1
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0

    .line 79
    sget-object v5, Lou/c;->a:Ljp/fc;

    .line 80
    .line 81
    :try_start_1
    invoke-virtual {v1, v2}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 82
    .line 83
    .line 84
    move-object v5, v4

    .line 85
    goto :goto_1

    .line 86
    :catch_1
    move-exception v5

    .line 87
    new-instance v6, Ljava/lang/StringBuilder;

    .line 88
    .line 89
    const-string v7, "Failed making constructor \'"

    .line 90
    .line 91
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    invoke-static {v1}, Lou/c;->b(Ljava/lang/reflect/Constructor;)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v7

    .line 98
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    const-string v7, "\' accessible; either increase its visibility or write a custom InstanceCreator or TypeAdapter for its declaring type: "

    .line 102
    .line 103
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    invoke-virtual {v5}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object v7

    .line 110
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-static {v5}, Lou/c;->e(Ljava/lang/Exception;)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v5

    .line 117
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v5

    .line 124
    :goto_1
    if-eqz v5, :cond_4

    .line 125
    .line 126
    new-instance v1, Lcom/google/gson/internal/a;

    .line 127
    .line 128
    invoke-direct {v1, v5, v2}, Lcom/google/gson/internal/a;-><init>(Ljava/lang/String;I)V

    .line 129
    .line 130
    .line 131
    goto :goto_2

    .line 132
    :cond_4
    new-instance v2, La8/t;

    .line 133
    .line 134
    const/16 v5, 0x10

    .line 135
    .line 136
    invoke-direct {v2, v1, v5}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 137
    .line 138
    .line 139
    move-object v1, v2

    .line 140
    :goto_2
    if-eqz v1, :cond_5

    .line 141
    .line 142
    return-object v1

    .line 143
    :cond_5
    const-class v1, Ljava/util/Collection;

    .line 144
    .line 145
    invoke-virtual {v1, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 146
    .line 147
    .line 148
    move-result v1

    .line 149
    if-eqz v1, :cond_9

    .line 150
    .line 151
    const-class v0, Ljava/util/ArrayList;

    .line 152
    .line 153
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 154
    .line 155
    .line 156
    move-result v0

    .line 157
    if-eqz v0, :cond_6

    .line 158
    .line 159
    new-instance v4, Lc1/y;

    .line 160
    .line 161
    const/16 v0, 0xc

    .line 162
    .line 163
    invoke-direct {v4, v0}, Lc1/y;-><init>(I)V

    .line 164
    .line 165
    .line 166
    goto/16 :goto_5

    .line 167
    .line 168
    :cond_6
    const-class v0, Ljava/util/LinkedHashSet;

    .line 169
    .line 170
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 171
    .line 172
    .line 173
    move-result v0

    .line 174
    if-eqz v0, :cond_7

    .line 175
    .line 176
    new-instance v4, Lc1/y;

    .line 177
    .line 178
    const/16 v0, 0xd

    .line 179
    .line 180
    invoke-direct {v4, v0}, Lc1/y;-><init>(I)V

    .line 181
    .line 182
    .line 183
    goto/16 :goto_5

    .line 184
    .line 185
    :cond_7
    const-class v0, Ljava/util/TreeSet;

    .line 186
    .line 187
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 188
    .line 189
    .line 190
    move-result v0

    .line 191
    if-eqz v0, :cond_8

    .line 192
    .line 193
    new-instance v4, Lc1/y;

    .line 194
    .line 195
    const/16 v0, 0xe

    .line 196
    .line 197
    invoke-direct {v4, v0}, Lc1/y;-><init>(I)V

    .line 198
    .line 199
    .line 200
    goto/16 :goto_5

    .line 201
    .line 202
    :cond_8
    const-class v0, Ljava/util/ArrayDeque;

    .line 203
    .line 204
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 205
    .line 206
    .line 207
    move-result v0

    .line 208
    if-eqz v0, :cond_10

    .line 209
    .line 210
    new-instance v4, Lc1/y;

    .line 211
    .line 212
    const/16 v0, 0xf

    .line 213
    .line 214
    invoke-direct {v4, v0}, Lc1/y;-><init>(I)V

    .line 215
    .line 216
    .line 217
    goto/16 :goto_5

    .line 218
    .line 219
    :cond_9
    const-class v1, Ljava/util/Map;

    .line 220
    .line 221
    invoke-virtual {v1, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 222
    .line 223
    .line 224
    move-result v1

    .line 225
    if-eqz v1, :cond_10

    .line 226
    .line 227
    const-class v1, Lcom/google/gson/internal/l;

    .line 228
    .line 229
    invoke-virtual {p1, v1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 230
    .line 231
    .line 232
    move-result v1

    .line 233
    if-eqz v1, :cond_c

    .line 234
    .line 235
    instance-of v1, v0, Ljava/lang/reflect/ParameterizedType;

    .line 236
    .line 237
    if-nez v1, :cond_a

    .line 238
    .line 239
    goto :goto_3

    .line 240
    :cond_a
    check-cast v0, Ljava/lang/reflect/ParameterizedType;

    .line 241
    .line 242
    invoke-interface {v0}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    .line 243
    .line 244
    .line 245
    move-result-object v0

    .line 246
    array-length v1, v0

    .line 247
    if-nez v1, :cond_b

    .line 248
    .line 249
    goto :goto_4

    .line 250
    :cond_b
    aget-object v0, v0, v3

    .line 251
    .line 252
    invoke-static {v0}, Lcom/google/gson/internal/f;->h(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    const-class v1, Ljava/lang/String;

    .line 257
    .line 258
    if-ne v0, v1, :cond_c

    .line 259
    .line 260
    :goto_3
    new-instance v4, Lc1/y;

    .line 261
    .line 262
    const/4 v0, 0x7

    .line 263
    invoke-direct {v4, v0}, Lc1/y;-><init>(I)V

    .line 264
    .line 265
    .line 266
    goto :goto_5

    .line 267
    :cond_c
    :goto_4
    const-class v0, Ljava/util/LinkedHashMap;

    .line 268
    .line 269
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 270
    .line 271
    .line 272
    move-result v0

    .line 273
    if-eqz v0, :cond_d

    .line 274
    .line 275
    new-instance v4, Lc1/y;

    .line 276
    .line 277
    const/16 v0, 0x8

    .line 278
    .line 279
    invoke-direct {v4, v0}, Lc1/y;-><init>(I)V

    .line 280
    .line 281
    .line 282
    goto :goto_5

    .line 283
    :cond_d
    const-class v0, Ljava/util/TreeMap;

    .line 284
    .line 285
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 286
    .line 287
    .line 288
    move-result v0

    .line 289
    if-eqz v0, :cond_e

    .line 290
    .line 291
    new-instance v4, Lc1/y;

    .line 292
    .line 293
    const/16 v0, 0x9

    .line 294
    .line 295
    invoke-direct {v4, v0}, Lc1/y;-><init>(I)V

    .line 296
    .line 297
    .line 298
    goto :goto_5

    .line 299
    :cond_e
    const-class v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 300
    .line 301
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 302
    .line 303
    .line 304
    move-result v0

    .line 305
    if-eqz v0, :cond_f

    .line 306
    .line 307
    new-instance v4, Lc1/y;

    .line 308
    .line 309
    const/16 v0, 0xa

    .line 310
    .line 311
    invoke-direct {v4, v0}, Lc1/y;-><init>(I)V

    .line 312
    .line 313
    .line 314
    goto :goto_5

    .line 315
    :cond_f
    const-class v0, Ljava/util/concurrent/ConcurrentSkipListMap;

    .line 316
    .line 317
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 318
    .line 319
    .line 320
    move-result v0

    .line 321
    if-eqz v0, :cond_10

    .line 322
    .line 323
    new-instance v4, Lc1/y;

    .line 324
    .line 325
    const/16 v0, 0xb

    .line 326
    .line 327
    invoke-direct {v4, v0}, Lc1/y;-><init>(I)V

    .line 328
    .line 329
    .line 330
    :cond_10
    :goto_5
    if-eqz v4, :cond_11

    .line 331
    .line 332
    return-object v4

    .line 333
    :cond_11
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/i4;->n(Ljava/lang/Class;)Ljava/lang/String;

    .line 334
    .line 335
    .line 336
    move-result-object v0

    .line 337
    if-eqz v0, :cond_12

    .line 338
    .line 339
    new-instance p0, Lcom/google/gson/internal/a;

    .line 340
    .line 341
    invoke-direct {p0, v0, v3}, Lcom/google/gson/internal/a;-><init>(Ljava/lang/String;I)V

    .line 342
    .line 343
    .line 344
    return-object p0

    .line 345
    :cond_12
    const-string v0, "Unable to create instance of "

    .line 346
    .line 347
    if-nez p2, :cond_13

    .line 348
    .line 349
    new-instance p0, Ljava/lang/StringBuilder;

    .line 350
    .line 351
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 352
    .line 353
    .line 354
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 355
    .line 356
    .line 357
    const-string p1, "; Register an InstanceCreator or a TypeAdapter for this type."

    .line 358
    .line 359
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 360
    .line 361
    .line 362
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 363
    .line 364
    .line 365
    move-result-object p0

    .line 366
    new-instance p1, Lcom/google/gson/internal/a;

    .line 367
    .line 368
    const/4 p2, 0x2

    .line 369
    invoke-direct {p1, p0, p2}, Lcom/google/gson/internal/a;-><init>(Ljava/lang/String;I)V

    .line 370
    .line 371
    .line 372
    return-object p1

    .line 373
    :cond_13
    iget-boolean p0, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 374
    .line 375
    if-eqz p0, :cond_14

    .line 376
    .line 377
    new-instance p0, La8/t;

    .line 378
    .line 379
    const/16 p2, 0x11

    .line 380
    .line 381
    invoke-direct {p0, p1, p2}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 382
    .line 383
    .line 384
    goto :goto_6

    .line 385
    :cond_14
    new-instance p0, Ljava/lang/StringBuilder;

    .line 386
    .line 387
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 388
    .line 389
    .line 390
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 391
    .line 392
    .line 393
    const-string p2, "; usage of JDK Unsafe is disabled. Registering an InstanceCreator or a TypeAdapter for this type, adding a no-args constructor, or enabling usage of JDK Unsafe may fix this problem."

    .line 394
    .line 395
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 396
    .line 397
    .line 398
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 399
    .line 400
    .line 401
    move-result-object p0

    .line 402
    invoke-virtual {p1}, Ljava/lang/Class;->getDeclaredConstructors()[Ljava/lang/reflect/Constructor;

    .line 403
    .line 404
    .line 405
    move-result-object p1

    .line 406
    array-length p1, p1

    .line 407
    if-nez p1, :cond_15

    .line 408
    .line 409
    const-string p1, " Or adjust your R8 configuration to keep the no-args constructor of the class."

    .line 410
    .line 411
    invoke-static {p0, p1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 412
    .line 413
    .line 414
    move-result-object p0

    .line 415
    :cond_15
    new-instance p1, Lcom/google/gson/internal/a;

    .line 416
    .line 417
    const/4 p2, 0x3

    .line 418
    invoke-direct {p1, p0, p2}, Lcom/google/gson/internal/a;-><init>(Ljava/lang/String;I)V

    .line 419
    .line 420
    .line 421
    move-object p0, p1

    .line 422
    :goto_6
    return-object p0

    .line 423
    :cond_16
    new-instance p0, Ljava/lang/ClassCastException;

    .line 424
    .line 425
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 426
    .line 427
    .line 428
    throw p0

    .line 429
    :cond_17
    new-instance p0, Ljava/lang/ClassCastException;

    .line 430
    .line 431
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 432
    .line 433
    .line 434
    throw p0
.end method

.method public s()Le2/j;
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/collection/h;

    .line 4
    .line 5
    iget v0, p0, Landroidx/collection/h;->e:I

    .line 6
    .line 7
    iget p0, p0, Landroidx/collection/h;->f:I

    .line 8
    .line 9
    if-ge v0, p0, :cond_0

    .line 10
    .line 11
    sget-object p0, Le2/j;->e:Le2/j;

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    if-le v0, p0, :cond_1

    .line 15
    .line 16
    sget-object p0, Le2/j;->d:Le2/j;

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_1
    sget-object p0, Le2/j;->f:Le2/j;

    .line 20
    .line 21
    return-object p0
.end method

.method public t()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Le2/w0;

    .line 8
    .line 9
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Lg4/o0;

    .line 12
    .line 13
    invoke-static {v0, p0}, Le2/w0;->a(Le2/w0;Lg4/o0;)V

    .line 14
    .line 15
    .line 16
    :cond_0
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/measurement/i4;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "SingleSelectionLayout(isStartHandle="

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", crossed="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/i4;->s()Le2/j;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v1, ", info=\n\t"

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Landroidx/collection/h;

    .line 43
    .line 44
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const/16 p0, 0x29

    .line 48
    .line 49
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p0, Ljava/util/Map;

    .line 60
    .line 61
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x4
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public x(Ll4/v;JZLc1/y;)J
    .locals 9

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Le2/w0;

    .line 5
    .line 6
    const/4 v6, 0x0

    .line 7
    const/4 v8, 0x0

    .line 8
    move-object v2, p1

    .line 9
    move-wide v3, p2

    .line 10
    move v5, p4

    .line 11
    move-object v7, p5

    .line 12
    invoke-static/range {v1 .. v8}, Le2/w0;->c(Le2/w0;Ll4/v;JZZLc1/y;Z)J

    .line 13
    .line 14
    .line 15
    move-result-wide p1

    .line 16
    iget-object p3, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p3, Lg4/o0;

    .line 19
    .line 20
    invoke-static {p1, p2, p3}, Lg4/o0;->a(JLjava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p3

    .line 24
    if-nez p3, :cond_0

    .line 25
    .line 26
    const/4 p3, 0x0

    .line 27
    iput-boolean p3, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 28
    .line 29
    :cond_0
    invoke-static {p1, p2}, Lg4/o0;->c(J)Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    if-eqz p0, :cond_1

    .line 34
    .line 35
    sget-object p0, Lt1/c0;->f:Lt1/c0;

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    sget-object p0, Lt1/c0;->e:Lt1/c0;

    .line 39
    .line 40
    :goto_0
    invoke-virtual {v1, p0}, Le2/w0;->p(Lt1/c0;)V

    .line 41
    .line 42
    .line 43
    return-wide p1
.end method

.method public declared-synchronized z()Lis/b;
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 3
    .line 4
    check-cast v0, Lis/b;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    return-object v0

    .line 8
    :goto_0
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 9
    throw v0

    .line 10
    :catchall_0
    move-exception v0

    .line 11
    goto :goto_0
.end method
