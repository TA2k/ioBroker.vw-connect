.class public interface abstract Lh0/z0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/t1;


# static fields
.field public static final C0:Lh0/g;

.field public static final D0:Lh0/g;

.field public static final E0:Lh0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lh0/g;

    .line 2
    .line 3
    const-string v1, "camerax.core.imageInput.inputFormat"

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
    sput-object v0, Lh0/z0;->C0:Lh0/g;

    .line 12
    .line 13
    new-instance v0, Lh0/g;

    .line 14
    .line 15
    const-string v1, "camerax.core.imageInput.secondaryInputFormat"

    .line 16
    .line 17
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Lh0/z0;->D0:Lh0/g;

    .line 21
    .line 22
    new-instance v0, Lh0/g;

    .line 23
    .line 24
    const-string v1, "camerax.core.imageInput.inputDynamicRange"

    .line 25
    .line 26
    const-class v2, Lb0/y;

    .line 27
    .line 28
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lh0/z0;->E0:Lh0/g;

    .line 32
    .line 33
    return-void
.end method


# virtual methods
.method public l()I
    .locals 1

    .line 1
    sget-object v0, Lh0/z0;->C0:Lh0/g;

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method
