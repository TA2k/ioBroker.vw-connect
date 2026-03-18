.class public final Lh0/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final h:Lh0/g;

.field public static final i:Lh0/g;

.field public static final j:Lh0/g;


# instance fields
.field public final a:Ljava/util/ArrayList;

.field public final b:Lh0/n1;

.field public final c:I

.field public final d:Ljava/util/List;

.field public final e:Z

.field public final f:Lh0/j2;

.field public final g:Lh0/s;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lh0/g;

    .line 2
    .line 3
    const-string v1, "camerax.core.captureConfig.rotation"

    .line 4
    .line 5
    sget-object v2, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lh0/o0;->h:Lh0/g;

    .line 12
    .line 13
    new-instance v0, Lh0/g;

    .line 14
    .line 15
    const-string v1, "camerax.core.captureConfig.jpegQuality"

    .line 16
    .line 17
    const-class v2, Ljava/lang/Integer;

    .line 18
    .line 19
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lh0/o0;->i:Lh0/g;

    .line 23
    .line 24
    new-instance v0, Lh0/g;

    .line 25
    .line 26
    const-string v1, "camerax.core.captureConfig.resolvedFrameRate"

    .line 27
    .line 28
    const-class v2, Landroid/util/Range;

    .line 29
    .line 30
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 31
    .line 32
    .line 33
    sput-object v0, Lh0/o0;->j:Lh0/g;

    .line 34
    .line 35
    return-void
.end method

.method public constructor <init>(Ljava/util/ArrayList;Lh0/n1;ILjava/util/ArrayList;ZLh0/j2;Lh0/s;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh0/o0;->a:Ljava/util/ArrayList;

    .line 5
    .line 6
    iput-object p2, p0, Lh0/o0;->b:Lh0/n1;

    .line 7
    .line 8
    iput p3, p0, Lh0/o0;->c:I

    .line 9
    .line 10
    invoke-static {p4}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iput-object p1, p0, Lh0/o0;->d:Ljava/util/List;

    .line 15
    .line 16
    iput-boolean p5, p0, Lh0/o0;->e:Z

    .line 17
    .line 18
    iput-object p6, p0, Lh0/o0;->f:Lh0/j2;

    .line 19
    .line 20
    iput-object p7, p0, Lh0/o0;->g:Lh0/s;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final a()Landroid/util/Range;
    .locals 2

    .line 1
    sget-object v0, Lh0/o0;->j:Lh0/g;

    .line 2
    .line 3
    sget-object v1, Lh0/k;->h:Landroid/util/Range;

    .line 4
    .line 5
    iget-object p0, p0, Lh0/o0;->b:Lh0/n1;

    .line 6
    .line 7
    invoke-virtual {p0, v0, v1}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Landroid/util/Range;

    .line 12
    .line 13
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    return-object p0
.end method

.method public final b()I
    .locals 2

    .line 1
    sget-object v0, Lh0/o2;->a1:Lh0/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    iget-object p0, p0, Lh0/o0;->b:Lh0/n1;

    .line 9
    .line 10
    invoke-virtual {p0, v0, v1}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0
.end method

.method public final c()I
    .locals 2

    .line 1
    sget-object v0, Lh0/o2;->b1:Lh0/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    iget-object p0, p0, Lh0/o0;->b:Lh0/n1;

    .line 9
    .line 10
    invoke-virtual {p0, v0, v1}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0
.end method
